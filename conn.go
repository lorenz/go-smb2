package smb2

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/hirochachacha/go-smb2/internal/erref"
	. "github.com/hirochachacha/go-smb2/internal/smb2"
)

// Negotiator contains options for func (*Dialer) Dial.
type Negotiator struct {
	RequireMessageSigning bool     // enforce signing?
	ClientGuid            [16]byte // if it's zero, generated by crypto/rand.
	SpecifiedDialect      uint16   // if it's zero, clientDialects is used. (See feature.go for more details)
}

func (n *Negotiator) makeRequest() (*NegotiateRequest, error) {
	req := new(NegotiateRequest)

	if n.RequireMessageSigning {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
	}

	req.Capabilities = clientCapabilities

	if n.ClientGuid == zero {
		_, err := rand.Read(req.ClientGuid[:])
		if err != nil {
			return nil, &InternalError{err.Error()}
		}
	} else {
		req.ClientGuid = n.ClientGuid
	}

	if n.SpecifiedDialect != UnknownSMB {
		req.Dialects = []uint16{n.SpecifiedDialect}

		switch n.SpecifiedDialect {
		case SMB202:
		case SMB210:
		case SMB300:
		case SMB302:
		case SMB311:
			hc := &HashContext{
				HashAlgorithms: clientHashAlgorithms,
				HashSalt:       make([]byte, 32),
			}
			if _, err := rand.Read(hc.HashSalt); err != nil {
				return nil, &InternalError{err.Error()}
			}

			cc := &CipherContext{
				Ciphers: clientCiphers,
			}

			req.Contexts = append(req.Contexts, hc, cc)
		default:
			return nil, &InternalError{"unsupported dialect specified"}
		}
	} else {
		req.Dialects = clientDialects

		hc := &HashContext{
			HashAlgorithms: clientHashAlgorithms,
			HashSalt:       make([]byte, 32),
		}
		if _, err := rand.Read(hc.HashSalt); err != nil {
			return nil, &InternalError{err.Error()}
		}

		cc := &CipherContext{
			Ciphers: clientCiphers,
		}

		req.Contexts = append(req.Contexts, hc, cc)
	}

	return req, nil
}

func (n *Negotiator) negotiate(t transport, a *account, ctx context.Context) (*conn, error) {
	conn := &conn{
		t:                   t,
		outstandingRequests: newOutstandingRequests(),
		account:             a,
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
	}

	go conn.runSender()
	go conn.runReciever()

retry:
	req, err := n.makeRequest()
	if err != nil {
		return nil, err
	}

	req.CreditCharge = 1

	rr, err := conn.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := conn.recv(rr)
	if err != nil {
		return nil, err
	}

	res, err := accept(SMB2_NEGOTIATE, pkt)
	if err != nil {
		return nil, err
	}

	r := NegotiateResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken negotiate response format"}
	}

	if r.DialectRevision() == SMB2 {
		n.SpecifiedDialect = SMB210

		goto retry
	}

	if n.SpecifiedDialect != UnknownSMB && n.SpecifiedDialect != r.DialectRevision() {
		return nil, &InvalidResponseError{"unexpected dialect returned"}
	}

	conn.requireSigning = n.RequireMessageSigning || r.SecurityMode()&SMB2_NEGOTIATE_SIGNING_REQUIRED != 0
	conn.capabilities = clientCapabilities & r.Capabilities()
	conn.dialect = r.DialectRevision()
	conn.maxTransactSize = r.MaxTransactSize()
	conn.maxReadSize = r.MaxReadSize()
	conn.maxWriteSize = r.MaxWriteSize()
	conn.sequenceWindow = 1

	// conn.gssNegotiateToken = r.SecurityBuffer()
	// conn.clientGuid = n.ClientGuid
	// copy(conn.serverGuid[:], r.ServerGuid())

	if conn.dialect != SMB311 {
		return conn, nil
	}

	// handle context for SMB311
	list := r.NegotiateContextList()
	for count := r.NegotiateContextCount(); count > 0; count-- {
		ctx := NegotiateContextDecoder(list)
		if ctx.IsInvalid() {
			return nil, &InvalidResponseError{"broken negotiate context format"}
		}

		switch ctx.ContextType() {
		case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
			d := HashContextDataDecoder(ctx.Data())
			if d.IsInvalid() {
				return nil, &InvalidResponseError{"broken hash context data format"}
			}

			algs := d.HashAlgorithms()

			if len(algs) != 1 {
				return nil, &InvalidResponseError{"multiple hash algorithms"}
			}

			conn.preauthIntegrityHashId = algs[0]

			switch conn.preauthIntegrityHashId {
			case SHA512:
				h := sha512.New()
				h.Write(conn.preauthIntegrityHashValue[:])
				h.Write(rr.pkt)
				h.Sum(conn.preauthIntegrityHashValue[:0])

				h.Reset()
				h.Write(conn.preauthIntegrityHashValue[:])
				h.Write(pkt)
				h.Sum(conn.preauthIntegrityHashValue[:0])
			default:
				return nil, &InvalidResponseError{"unknown hash algorithm"}
			}
		case SMB2_ENCRYPTION_CAPABILITIES:
			d := CipherContextDataDecoder(ctx.Data())
			if d.IsInvalid() {
				return nil, &InvalidResponseError{"broken cipher context data format"}
			}

			ciphs := d.Ciphers()

			if len(ciphs) != 1 {
				return nil, &InvalidResponseError{"multiple cipher algorithms"}
			}

			conn.cipherId = ciphs[0]

			switch conn.cipherId {
			case AES128CCM:
			case AES128GCM:
			default:
				return nil, &InvalidResponseError{"unknown cipher algorithm"}
			}
		default:
			// skip unsupported context
		}

		off := ctx.Next()

		if len(list) < off {
			list = nil
		} else {
			list = list[off:]
		}
	}

	return conn, nil
}

type requestResponse struct {
	msgId         uint64
	asyncId       uint64
	creditRequest uint16
	pkt           []byte // request packet
	ctx           context.Context
	recv          chan []byte
	err           error
}

type outstandingRequests struct {
	m        sync.Mutex
	requests map[uint64]*requestResponse
}

func newOutstandingRequests() *outstandingRequests {
	return &outstandingRequests{
		requests: make(map[uint64]*requestResponse, 0),
	}
}

func (r *outstandingRequests) pop(msgId uint64) (*requestResponse, bool) {
	r.m.Lock()
	defer r.m.Unlock()

	rr, ok := r.requests[msgId]
	if !ok {
		return nil, false
	}

	delete(r.requests, msgId)

	return rr, true
}

func (r *outstandingRequests) set(msgId uint64, rr *requestResponse) {
	r.m.Lock()
	defer r.m.Unlock()

	r.requests[msgId] = rr
}

func (r *outstandingRequests) shutdown(err error) {
	r.m.Lock()
	defer r.m.Unlock()

	for _, rr := range r.requests {
		rr.err = err
		close(rr.recv)
	}
}

type conn struct {
	t transport

	session                   *session
	outstandingRequests       *outstandingRequests
	sequenceWindow            uint64
	dialect                   uint16
	maxTransactSize           uint32
	maxReadSize               uint32
	maxWriteSize              uint32
	requireSigning            bool
	capabilities              uint32
	preauthIntegrityHashId    uint16
	preauthIntegrityHashValue [64]byte
	cipherId                  uint16

	account *account

	rdone chan struct{}
	wdone chan struct{}
	write chan []byte
	werr  chan error

	m sync.Mutex

	err error

	// gssNegotiateToken []byte
	// serverGuid        [16]byte
	// clientGuid        [16]byte

	_useSession int32 // receiver use session?
}

func (conn *conn) useSession() bool {
	return atomic.LoadInt32(&conn._useSession) != 0
}

func (conn *conn) enableSession() {
	atomic.StoreInt32(&conn._useSession, 1)
}

func (conn *conn) newTimer() *time.Timer {
	return time.NewTimer(5 * time.Second)
}

func (conn *conn) sendRecv(cmd uint16, req Packet, ctx context.Context) (res []byte, err error) {
	rr, err := conn.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := conn.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

func (conn *conn) loanCredit(payloadSize int, ctx context.Context) (creditCharge uint16, grantedPayloadSize int, err error) {
	if conn.capabilities&SMB2_GLOBAL_CAP_LARGE_MTU == 0 {
		creditCharge = 1
	} else {
		creditCharge = uint16((payloadSize-1)/(64*1024) + 1)
	}

	creditCharge, isComplete, err := conn.account.loan(creditCharge, ctx)
	if err != nil {
		return creditCharge, 0, err
	}
	if isComplete {
		return creditCharge, payloadSize, nil
	}

	return creditCharge, 64 * 1024 * int(creditCharge), nil
}

func (conn *conn) chargeCredit(creditCharge uint16) {
	conn.account.charge(creditCharge, creditCharge)
}

func (conn *conn) send(req Packet, ctx context.Context) (rr *requestResponse, err error) {
	return conn.sendWith(req, nil, ctx)
}

func (conn *conn) sendWith(req Packet, tc *treeConn, ctx context.Context) (rr *requestResponse, err error) {
	conn.m.Lock()
	defer conn.m.Unlock()

	if conn.err != nil {
		return nil, conn.err
	}

	select {
	case <-ctx.Done():
		return nil, &ContextError{Err: ctx.Err()}
	default:
		// do nothing
	}

	rr, err = conn.makeRequestResponse(req, tc, ctx)
	if err != nil {
		return nil, err
	}

	select {
	case conn.write <- rr.pkt:
		select {
		case err = <-conn.werr:
			if err != nil {
				conn.outstandingRequests.pop(rr.msgId)

				return nil, &TransportError{err}
			}
		case <-ctx.Done():
			conn.outstandingRequests.pop(rr.msgId)

			return nil, &ContextError{Err: ctx.Err()}
		}
	case <-ctx.Done():
		conn.outstandingRequests.pop(rr.msgId)

		return nil, &ContextError{Err: ctx.Err()}
	}

	return rr, nil
}

func (conn *conn) makeRequestResponse(req Packet, tc *treeConn, ctx context.Context) (rr *requestResponse, err error) {
	hdr := req.Header()

	var msgId uint64

	if _, ok := req.(*CancelRequest); !ok {
		msgId = conn.sequenceWindow

		creditCharge := hdr.CreditCharge

		conn.sequenceWindow += uint64(creditCharge)
		if hdr.CreditRequestResponse == 0 {
			hdr.CreditRequestResponse = creditCharge
		}

		hdr.CreditRequestResponse += conn.account.opening()
	}

	hdr.MessageId = msgId

	s := conn.session

	if s != nil {
		hdr.SessionId = s.sessionId

		if tc != nil {
			hdr.TreeId = tc.treeId
		}
	}

	pkt := make([]byte, req.Size())

	req.Encode(pkt)

	if s != nil {
		if _, ok := req.(*SessionSetupRequest); !ok {
			if s.sessionFlags&SMB2_SESSION_FLAG_ENCRYPT_DATA != 0 || (tc != nil && tc.shareFlags&SMB2_SHAREFLAG_ENCRYPT_DATA != 0) {
				pkt, err = s.encrypt(pkt)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
			} else {
				if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
					pkt = s.sign(pkt)
				}
			}
		}
	}

	rr = &requestResponse{
		msgId:         msgId,
		creditRequest: hdr.CreditRequestResponse,
		pkt:           pkt,
		ctx:           ctx,
		recv:          make(chan []byte, 1),
	}

	conn.outstandingRequests.set(msgId, rr)

	return rr, nil
}

func (conn *conn) recv(rr *requestResponse) ([]byte, error) {
	select {
	case pkt := <-rr.recv:
		if rr.err != nil {
			return nil, rr.err
		}
		return pkt, nil
	case <-rr.ctx.Done():
		conn.outstandingRequests.pop(rr.msgId)

		return nil, &ContextError{Err: rr.ctx.Err()}
	}
}

func (conn *conn) runSender() {
	for {
		select {
		case <-conn.wdone:
			return
		case pkt := <-conn.write:
			conn.t.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err := conn.t.Write(pkt)

			conn.werr <- err
		}
	}
}

func (conn *conn) runReciever() {
	var err error

	pkt := make([]byte, 4096)

	for {
		n, e := conn.t.ReadSize()
		if e != nil {
			err = &TransportError{e}

			goto exit
		}

		for cap(pkt) < (n + 16) {
			pkt = append(pkt[:cap(pkt)], 0)
		}

		pkt := pkt[:n]

		_, e = conn.t.Read(pkt)
		if e != nil {
			err = &TransportError{e}

			goto exit
		}

		hasSession := conn.useSession()

		var isEncrypted bool

		if hasSession {
			pkt, e, isEncrypted = conn.tryDecrypt(pkt)
			if e != nil {
				logger.Println("skip:", e)

				continue
			}

			p := PacketCodec(pkt)
			if s := conn.session; s != nil {
				if s.sessionId != p.SessionId() {
					logger.Println("skip:", &InvalidResponseError{"unknown session id"})

					continue
				}

				if tc, ok := s.treeConnTables[p.TreeId()]; ok {
					if tc.treeId != p.TreeId() {
						logger.Println("skip:", &InvalidResponseError{"unknown tree id"})

						continue
					}
				}
			}
		}

		var next []byte

		for {
			p := PacketCodec(pkt)

			if off := p.NextCommand(); off != 0 {
				pkt, next = pkt[:off], pkt[off:]
			} else {
				next = nil
			}

			if hasSession {
				e = conn.tryVerify(pkt, isEncrypted)
			}

			e = conn.tryHandle(pkt, e)
			if e != nil {
				logger.Println("skip:", e)
			}

			if next == nil {
				break
			}

			pkt = next
		}
	}

exit:
	select {
	case <-conn.rdone:
		err = fmt.Errorf("session closed due to: %w", err)
	default:
		logger.Println("error:", err)
	}

	conn.m.Lock()
	defer conn.m.Unlock()

	conn.outstandingRequests.shutdown(err)

	conn.err = err

	close(conn.wdone)
}

func accept(cmd uint16, pkt []byte) (res []byte, err error) {
	p := PacketCodec(pkt)
	if command := p.Command(); cmd != command {
		return nil, &InvalidResponseError{fmt.Sprintf("expected command: %v, got %v", cmd, command)}
	}

	status := NtStatus(p.Status())

	switch status {
	case STATUS_SUCCESS:
		return p.Data(), nil
	case STATUS_OBJECT_NAME_COLLISION:
		return nil, os.ErrExist
	case STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND:
		return nil, os.ErrNotExist
	case STATUS_ACCESS_DENIED, STATUS_CANNOT_DELETE:
		return nil, os.ErrPermission
	}

	switch cmd {
	case SMB2_SESSION_SETUP:
		if status == STATUS_MORE_PROCESSING_REQUIRED {
			return p.Data(), nil
		}
	case SMB2_QUERY_INFO:
		if status == STATUS_BUFFER_OVERFLOW {
			return nil, &ResponseError{Code: uint32(status)}
		}
	case SMB2_IOCTL:
		if status == STATUS_BUFFER_OVERFLOW {
			if !IoctlResponseDecoder(p.Data()).IsInvalid() {
				return p.Data(), &ResponseError{Code: uint32(status)}
			}
		}
	case SMB2_READ:
		if status == STATUS_BUFFER_OVERFLOW {
			return nil, &ResponseError{Code: uint32(status)}
		}
	case SMB2_CHANGE_NOTIFY:
		if status == STATUS_NOTIFY_ENUM_DIR {
			return nil, &ResponseError{Code: uint32(status)}
		}
	}

	return nil, acceptError(uint32(status), p.Data())
}

func acceptError(status uint32, res []byte) error {
	r := ErrorResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken error response format"}
	}

	eData := r.ErrorData()

	if count := r.ErrorContextCount(); count != 0 {
		data := make([][]byte, count)
		for i := range data {
			ctx := ErrorContextResponseDecoder(eData)
			if ctx.IsInvalid() {
				return &InvalidResponseError{"broken error context response format"}
			}

			data[i] = ctx.ErrorContextData()

			next := ctx.Next()

			if len(eData) < next {
				return &InvalidResponseError{"broken error context response format"}
			}

			eData = eData[next:]
		}
		return &ResponseError{Code: status, data: data}
	}
	return &ResponseError{Code: status, data: [][]byte{eData}}
}

func (conn *conn) tryDecrypt(pkt []byte) ([]byte, error, bool) {
	p := PacketCodec(pkt)
	if p.IsInvalid() {
		t := TransformCodec(pkt)
		if t.IsInvalid() {
			return nil, &InvalidResponseError{"broken packet header format"}, false
		}

		if t.Flags() != Encrypted {
			return nil, &InvalidResponseError{"encrypted flag is not on"}, false
		}

		if conn.session == nil || conn.session.sessionId != t.SessionId() {
			return nil, &InvalidResponseError{"unknown session id returned"}, false
		}

		pkt, err := conn.session.decrypt(pkt)
		if err != nil {
			return nil, &InvalidResponseError{err.Error()}, false
		}

		return pkt, nil, true
	}

	return pkt, nil, false
}

func (conn *conn) tryVerify(pkt []byte, isEncrypted bool) error {
	p := PacketCodec(pkt)

	msgId := p.MessageId()

	if msgId != 0xFFFFFFFFFFFFFFFF {
		if p.Flags()&SMB2_FLAGS_SIGNED != 0 {
			if conn.session == nil || conn.session.sessionId != p.SessionId() {
				return &InvalidResponseError{"unknown session id returned"}
			} else {
				if !conn.session.verify(pkt) {
					return &InvalidResponseError{"unverified packet returned"}
				}
			}
		} else {
			if conn.requireSigning && !isEncrypted {
				if conn.session != nil {
					if conn.session.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
						if conn.session.sessionId == p.SessionId() {
							return &InvalidResponseError{"signing required"}
						}
					}
				}
			}
		}
	}

	return nil
}

func (conn *conn) tryHandle(pkt []byte, e error) error {
	p := PacketCodec(pkt)

	msgId := p.MessageId()

	rr, ok := conn.outstandingRequests.pop(msgId)
	switch {
	case !ok:
		return &InvalidResponseError{"unknown message id returned"}
	case e != nil:
		rr.err = e

		close(rr.recv)
	case NtStatus(p.Status()) == STATUS_PENDING:
		rr.asyncId = p.AsyncId()
		conn.account.charge(p.CreditResponse(), rr.creditRequest)
		conn.outstandingRequests.set(msgId, rr)
	default:
		conn.account.charge(p.CreditResponse(), rr.creditRequest)

		rr.recv <- pkt
	}

	return nil
}
