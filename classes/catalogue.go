// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import "sort"

// Class is one interface class as data: its number, the version this
// package implements, its attributes and methods, and the short-name
// offset of its first method.
type Class struct {
	ID         uint16
	Version    uint8
	Name       string
	Attributes []Attribute
	Methods    []Method
	// FirstMethodSN is the short-name offset of method 1 from the object's base
	// name; 0 when the class has no methods or the offset is not known
	// here (see the comment on each such class).
	FirstMethodSN uint16
}

// Attribute is one attribute of a class. Static attributes are
// configuration that rarely changes; the others are values that move.
type Attribute struct {
	Index  int8
	Name   string
	Static bool
}

// Method is one method of a class.
type Method struct {
	Index int8
	Name  string
}

// Attribute returns attribute i of the class.
func (c *Class) Attribute(i int8) (Attribute, bool) {
	for _, a := range c.Attributes {
		if a.Index == i {
			return a, true
		}
	}
	return Attribute{}, false
}

// Method returns method i of the class.
func (c *Class) Method(i int8) (Method, bool) {
	for _, m := range c.Methods {
		if m.Index == i {
			return m, true
		}
	}
	return Method{}, false
}

// AttributeSN is the short-name offset of attribute i from the base name.
func (c *Class) AttributeSN(i int8) uint16 {
	return uint16(i-1) * 8
}

// MethodSN is the short-name offset of method i from the base name; false
// when the class has no such method or its method offset is not known.
func (c *Class) MethodSN(i int8) (uint16, bool) {
	if c.FirstMethodSN == 0 {
		return 0, false
	}
	if _, ok := c.Method(i); !ok {
		return 0, false
	}
	return c.FirstMethodSN + uint16(i-1)*8, true
}

// Lookup returns class id from the catalogue.
func Lookup(id uint16) (*Class, bool) {
	c, ok := byID[id]
	return c, ok
}

// All returns every class of the catalogue in ascending class order.
func All() []*Class {
	out := make([]*Class, 0, len(catalogue))
	for i := range catalogue {
		out = append(out, &catalogue[i])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

var byID = func() map[uint16]*Class {
	m := make(map[uint16]*Class, len(catalogue))
	for i := range catalogue {
		m[catalogue[i].ID] = &catalogue[i]
	}
	return m
}()

// Short constructors keep the table readable.
func st(i int8, name string) Attribute { return Attribute{Index: i, Name: name, Static: true} }
func dy(i int8, name string) Attribute { return Attribute{Index: i, Name: name} }
func me(i int8, name string) Method    { return Method{Index: i, Name: name} }

var lnAttr = st(1, "logicalName")

// catalogue lists the classes this package knows. Numbers (class,
// version, attribute and method indexes, short-name offsets) are facts of
// IEC 62056-6-2:2023 (Blue Book edition 15); the names are ours.
// Classes whose attribute list we could not confirm are left out rather
// than guessed: Account (111), Charge (113) and M-Bus slave port setup
// (25) among them.
var catalogue = []Class{
	{ID: 1, Version: 0, Name: "data", Attributes: []Attribute{lnAttr, dy(2, "value")}},
	{ID: 3, Version: 0, Name: "register", FirstMethodSN: 0x28,
		Attributes: []Attribute{lnAttr, dy(2, "value"), st(3, "scalerUnit")},
		Methods:    []Method{me(1, "reset")}},
	{ID: 4, Version: 0, Name: "extendedRegister", FirstMethodSN: 0x38,
		Attributes: []Attribute{lnAttr, dy(2, "value"), st(3, "scalerUnit"), dy(4, "status"), dy(5, "captureTime")},
		Methods:    []Method{me(1, "reset")}},
	{ID: 5, Version: 0, Name: "demandRegister", FirstMethodSN: 0x48,
		Attributes: []Attribute{lnAttr, dy(2, "currentAverageValue"), dy(3, "lastAverageValue"), st(4, "scalerUnit"),
			dy(5, "status"), dy(6, "captureTime"), dy(7, "startTimeCurrent"), st(8, "period"), st(9, "numberOfPeriods")},
		Methods: []Method{me(1, "reset"), me(2, "nextPeriod")}},
	{ID: 6, Version: 0, Name: "registerActivation", FirstMethodSN: 0x30,
		Attributes: []Attribute{lnAttr, st(2, "registerAssignment"), st(3, "maskList"), dy(4, "activeMask")},
		Methods:    []Method{me(1, "addRegister"), me(2, "addMask"), me(3, "deleteMask")}},
	{ID: 7, Version: 1, Name: "profileGeneric", FirstMethodSN: 0x58,
		Attributes: []Attribute{lnAttr, dy(2, "buffer"), st(3, "captureObjects"), st(4, "capturePeriod"),
			st(5, "sortMethod"), st(6, "sortObject"), dy(7, "entriesInUse"), st(8, "profileEntries")},
		Methods: []Method{me(1, "reset"), me(2, "capture")}},
	{ID: 8, Version: 0, Name: "clock", FirstMethodSN: 0x60,
		Attributes: []Attribute{lnAttr, dy(2, "time"), st(3, "timeZone"), dy(4, "status"), st(5, "daylightSavingsBegin"),
			st(6, "daylightSavingsEnd"), st(7, "daylightSavingsDeviation"), st(8, "daylightSavingsEnabled"), st(9, "clockBase")},
		Methods: []Method{me(1, "adjustToQuarter"), me(2, "adjustToMeasuringPeriod"), me(3, "adjustToMinute"),
			me(4, "adjustToPresetTime"), me(5, "presetAdjustingTime"), me(6, "shiftTime")}},
	{ID: 9, Version: 0, Name: "scriptTable", FirstMethodSN: 0x20,
		Attributes: []Attribute{lnAttr, st(2, "scripts")},
		Methods:    []Method{me(1, "execute")}},
	// Schedule: the short-name offset of its methods is not recorded here.
	{ID: 10, Version: 0, Name: "schedule",
		Attributes: []Attribute{lnAttr, st(2, "entries")},
		Methods:    []Method{me(1, "enableDisable"), me(2, "insert"), me(3, "delete")}},
	{ID: 11, Version: 0, Name: "specialDaysTable", FirstMethodSN: 0x10,
		Attributes: []Attribute{lnAttr, st(2, "entries")},
		Methods:    []Method{me(1, "insert"), me(2, "delete")}},
	// Association SN: methods 1, 2 and 7 are reserved and left out.
	{ID: 12, Version: 4, Name: "associationSN", FirstMethodSN: 0x20,
		Attributes: []Attribute{lnAttr, dy(2, "objectList"), dy(3, "accessRightsList"), st(4, "securitySetupReference"),
			st(5, "userList"), dy(6, "currentUser")},
		Methods: []Method{me(3, "readByLogicalName"), me(4, "getAttributesAndServices"), me(5, "changeLLSSecret"),
			me(6, "changeHLSSecret"), me(8, "replyToHLSAuthentication"), me(9, "addUser"), me(10, "removeUser")}},
	{ID: 15, Version: 3, Name: "associationLN", FirstMethodSN: 0x60,
		Attributes: []Attribute{lnAttr, dy(2, "objectList"), st(3, "associatedPartnersID"), st(4, "applicationContextName"),
			st(5, "xdlmsContextInfo"), st(6, "authenticationMechanismName"), st(7, "secret"), dy(8, "associationStatus"),
			st(9, "securitySetupReference"), st(10, "userList"), dy(11, "currentUser")},
		Methods: []Method{me(1, "replyToHLSAuthentication"), me(2, "changeHLSSecret"), me(3, "addObject"),
			me(4, "removeObject"), me(5, "addUser"), me(6, "removeUser")}},
	{ID: 17, Version: 0, Name: "sapAssignment", FirstMethodSN: 0x20,
		Attributes: []Attribute{lnAttr, st(2, "sapAssignmentList")},
		Methods:    []Method{me(1, "connectLogicalDevice")}},
	{ID: 18, Version: 0, Name: "imageTransfer", FirstMethodSN: 0x40,
		Attributes: []Attribute{lnAttr, st(2, "imageBlockSize"), dy(3, "transferredBlocksStatus"),
			dy(4, "firstNotTransferredBlockNumber"), st(5, "transferEnabled"), dy(6, "transferStatus"), dy(7, "toActivateInfo")},
		Methods: []Method{me(1, "initiate"), me(2, "blockTransfer"), me(3, "verify"), me(4, "activate")}},
	{ID: 19, Version: 1, Name: "iecLocalPortSetup",
		Attributes: []Attribute{lnAttr, st(2, "defaultMode"), st(3, "defaultBaud"), st(4, "proposedBaud"), st(5, "responseTime"),
			st(6, "deviceAddress"), st(7, "passwordP1"), st(8, "passwordP2"), st(9, "passwordW5")}},
	{ID: 20, Version: 0, Name: "activityCalendar", FirstMethodSN: 0x50,
		Attributes: []Attribute{lnAttr, st(2, "calendarNameActive"), st(3, "seasonProfileActive"), st(4, "weekProfileTableActive"),
			st(5, "dayProfileTableActive"), st(6, "calendarNamePassive"), st(7, "seasonProfilePassive"),
			st(8, "weekProfileTablePassive"), st(9, "dayProfileTablePassive"), st(10, "activatePassiveCalendarTime")},
		Methods: []Method{me(1, "activatePassiveCalendar")}},
	{ID: 21, Version: 0, Name: "registerMonitor",
		Attributes: []Attribute{lnAttr, st(2, "thresholds"), st(3, "monitoredValue"), st(4, "actions")}},
	{ID: 22, Version: 0, Name: "singleActionSchedule",
		Attributes: []Attribute{lnAttr, st(2, "executedScript"), st(3, "type"), st(4, "executionTime")}},
	{ID: 23, Version: 1, Name: "iecHDLCSetup",
		Attributes: []Attribute{lnAttr, st(2, "commSpeed"), st(3, "windowSizeTransmit"), st(4, "windowSizeReceive"),
			st(5, "maxInfoFieldLengthTransmit"), st(6, "maxInfoFieldLengthReceive"), st(7, "interOctetTimeout"),
			st(8, "inactivityTimeout"), st(9, "deviceAddress")}},
	{ID: 26, Version: 0, Name: "utilityTables",
		Attributes: []Attribute{lnAttr, st(2, "tableID"), dy(3, "length"), dy(4, "buffer")}},
	{ID: 27, Version: 1, Name: "modemConfiguration",
		Attributes: []Attribute{lnAttr, st(2, "commSpeed"), st(3, "initialisationString"), st(4, "modemProfile")}},
	{ID: 28, Version: 2, Name: "autoAnswer",
		Attributes: []Attribute{lnAttr, st(2, "mode"), st(3, "listeningWindow"), dy(4, "status"), st(5, "numberOfCalls"),
			st(6, "numberOfRings"), st(7, "allowedCallers")}},
	// Auto connect: the short-name offset of its method is not recorded here.
	{ID: 29, Version: 2, Name: "autoConnect",
		Attributes: []Attribute{lnAttr, st(2, "mode"), st(3, "repetitions"), st(4, "repetitionDelay"), st(5, "callingWindow"),
			st(6, "destinationList")},
		Methods: []Method{me(1, "connect")}},
	// Push setup: version 0 (attributes 1 to 7 and push), the form IS 15959
	// meters carry. Later versions add attributes 8 and up; they are not
	// listed here.
	{ID: 40, Version: 0, Name: "pushSetup", FirstMethodSN: 0x38,
		Attributes: []Attribute{lnAttr, st(2, "pushObjectList"), st(3, "sendDestinationAndMethod"), st(4, "communicationWindow"),
			st(5, "randomisationStartInterval"), st(6, "numberOfRetries"), st(7, "repetitionDelay")},
		Methods: []Method{me(1, "push")}},
	{ID: 41, Version: 0, Name: "tcpUDPSetup",
		Attributes: []Attribute{lnAttr, st(2, "port"), st(3, "ipReference"), st(4, "mss"), st(5, "maxSimultaneousConnections"),
			st(6, "inactivityTimeout")}},
	{ID: 42, Version: 0, Name: "ipv4Setup", FirstMethodSN: 0x60,
		Attributes: []Attribute{lnAttr, st(2, "dataLinkReference"), dy(3, "ipAddress"), st(4, "multicastIPAddresses"),
			st(5, "ipOptions"), st(6, "subnetMask"), st(7, "gatewayIPAddress"), st(8, "useDHCP"), st(9, "primaryDNSAddress"),
			st(10, "secondaryDNSAddress")},
		Methods: []Method{me(1, "addMulticastIPAddress"), me(2, "deleteMulticastIPAddress"), me(3, "multicastIPAddressCount")}},
	{ID: 43, Version: 0, Name: "macAddressSetup", Attributes: []Attribute{lnAttr, st(2, "macAddress")}},
	{ID: 44, Version: 0, Name: "pppSetup",
		Attributes: []Attribute{lnAttr, st(2, "physicalReference"), st(3, "lcpOptions"), st(4, "ipcpOptions"), st(5, "pppAuthentication")}},
	{ID: 45, Version: 0, Name: "gprsModemSetup",
		Attributes: []Attribute{lnAttr, st(2, "apn"), st(3, "pinCode"), st(4, "qualityOfService")}},
	// GSM diagnostic: the attribute numbers are the same in versions 0 to
	// 2; version 1 is recorded until the current version is confirmed.
	{ID: 47, Version: 1, Name: "gsmDiagnostic",
		Attributes: []Attribute{lnAttr, dy(2, "operator"), dy(3, "status"), dy(4, "csAttachment"), dy(5, "psStatus"),
			dy(6, "cellInfo"), dy(7, "adjacentCells"), dy(8, "captureTime")}},
	{ID: 61, Version: 0, Name: "registerTable", FirstMethodSN: 0x28,
		Attributes: []Attribute{lnAttr, dy(2, "tableCellValues"), st(3, "tableCellDefinition"), st(4, "scalerUnit")},
		Methods:    []Method{me(1, "reset"), me(2, "capture")}},
	{ID: 63, Version: 0, Name: "statusMapping",
		Attributes: []Attribute{lnAttr, dy(2, "statusWord"), st(3, "mappingTable")}},
	{ID: 64, Version: 1, Name: "securitySetup", FirstMethodSN: 0x30,
		Attributes: []Attribute{lnAttr, st(2, "securityPolicy"), st(3, "securitySuite"), st(4, "clientSystemTitle"),
			st(5, "serverSystemTitle"), st(6, "certificates")},
		Methods: []Method{me(1, "securityActivate"), me(2, "keyTransfer"), me(3, "keyAgreement"), me(4, "generateKeyPair"),
			me(5, "generateCertificateRequest"), me(6, "importCertificate"), me(7, "exportCertificate"), me(8, "removeCertificate")}},
	// Arbitrator: the short-name offset of its methods is not recorded here.
	{ID: 68, Version: 0, Name: "arbitrator",
		Attributes: []Attribute{lnAttr, st(2, "actions"), st(3, "permissionsTable"), st(4, "weightingsTable"),
			dy(5, "mostRecentRequestsTable"), dy(6, "lastOutcome")},
		Methods: []Method{me(1, "request"), me(2, "reset")}},
	{ID: 70, Version: 0, Name: "disconnectControl", FirstMethodSN: 0x20,
		Attributes: []Attribute{lnAttr, dy(2, "outputState"), dy(3, "controlState"), st(4, "controlMode")},
		Methods:    []Method{me(1, "remoteDisconnect"), me(2, "remoteReconnect")}},
	{ID: 71, Version: 0, Name: "limiter",
		Attributes: []Attribute{lnAttr, st(2, "monitoredValue"), dy(3, "thresholdActive"), st(4, "thresholdNormal"),
			st(5, "thresholdEmergency"), st(6, "minOverThresholdDuration"), st(7, "minUnderThresholdDuration"),
			st(8, "emergencyProfile"), st(9, "emergencyProfileGroupIDs"), dy(10, "emergencyProfileActive"), st(11, "actions")}},
	// M-Bus client: the short-name offset of its methods is not recorded here.
	{ID: 72, Version: 1, Name: "mbusClient",
		Attributes: []Attribute{lnAttr, st(2, "mbusPortReference"), st(3, "captureDefinition"), st(4, "capturePeriod"),
			st(5, "primaryAddress"), st(6, "identificationNumber"), st(7, "manufacturerID"), st(8, "version"),
			st(9, "deviceType"), dy(10, "accessNumber"), dy(11, "status"), dy(12, "alarm"), st(13, "configuration"),
			dy(14, "encryptionKeyStatus")},
		Methods: []Method{me(1, "slaveInstall"), me(2, "slaveDeinstall"), me(3, "capture"), me(4, "resetAlarm"),
			me(5, "synchroniseClock"), me(6, "dataSend"), me(7, "setEncryptionKey"), me(8, "transferKey")}},
	{ID: 100, Version: 0, Name: "ntpSetup", FirstMethodSN: 0x38,
		Attributes: []Attribute{lnAttr, st(2, "activated"), st(3, "serverAddress"), st(4, "serverPort"),
			st(5, "authenticationMethod"), st(6, "authenticationKeys"), st(7, "clientKey")},
		Methods: []Method{me(1, "synchronise"), me(2, "addAuthenticationKey"), me(3, "deleteAuthenticationKey")}},
	// Credit: the short-name offset of its methods is not recorded here.
	{ID: 112, Version: 0, Name: "credit",
		Attributes: []Attribute{lnAttr, dy(2, "currentCreditAmount"), st(3, "creditType"), st(4, "priority"),
			st(5, "warningThreshold"), st(6, "limit"), st(7, "creditConfiguration"), dy(8, "creditStatus"),
			st(9, "presetCreditAmount"), st(10, "creditAvailableThreshold"), st(11, "period")},
		Methods: []Method{me(1, "updateAmount"), me(2, "setAmountToValue"), me(3, "invokeCredit")}},
	// Token gateway: the short-name offset of its method is not recorded here.
	{ID: 115, Version: 0, Name: "tokenGateway",
		Attributes: []Attribute{lnAttr, dy(2, "token"), dy(3, "tokenTime"), dy(4, "tokenDescription"),
			st(5, "tokenDeliveryMethod"), dy(6, "tokenStatus")},
		Methods: []Method{me(1, "enter")}},
}
