package common_def

// GprotoAddrMsg is Gproto "CONNECT" message
type GprotoAddrMsg struct {
	Ver      [2]byte
	Command  byte
	AddrType byte
	AddrLen  byte
	Addr     []byte
}

// GprotoConnMsg is Gproto "STATUS" message
type GprotoConnMsg struct {
	Ver     [2]byte
	Command byte
	Status  byte
}

// ToByteSlice serializes a Gproto CONNECT message to []byte
func (g *GprotoAddrMsg) ToByteSlice() []byte {
	buf := make([]byte, 5+int(g.AddrLen))
	copy(buf[:2], g.Ver[:])
	buf[2] = g.Command
	buf[3] = g.AddrType
	buf[4] = g.AddrLen
	copy(buf[5:], g.Addr)

	return buf
}

// ToByteSlice serializes a Gproto STATUS message to []byte
func (g *GprotoConnMsg) ToByteSlice() []byte {
	buf := make([]byte, 4)
	copy(buf[:2], g.Ver[:])
	buf[2] = g.Command
	buf[3] = g.Status

	return buf
}
