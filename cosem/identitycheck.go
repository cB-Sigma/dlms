package cosem

// Identity check of meters that name no system title. With HLS and
// protected APDUs the AARE's calling AP title tells which meter answered
// (secure.go, expectST). A meter with low-level or no security sends none,
// and meters often share one password: a meter now holding another's
// address would complete the association and execute its commands. With
// an identity check, a value the meter keeps (its serial number by
// default) is read after every association (ReadIdentity, as the Check of
// an AssociationConfig) and compared with the expected one.

// IdentityCheck is a meter's identity check: Expect is the value
// expected, OBIS the Data object read (default 0.0.96.1.0.255, the serial
// number; 0.0.42.0.0.255 is the logical device name), and OnMismatch
// refuse (default: the association is not used) or warn.
type IdentityCheck struct {
	Expect     string `json:"expect,omitempty"`
	OBIS       string `json:"obis,omitempty"`
	OnMismatch string `json:"onMismatch,omitempty"`
}
