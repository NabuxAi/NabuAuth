package sms

import "testing"

// The country selector is only as real as this function. Everything the visitor
// picks arrives here as a calling code, and what comes out is the string that
// keys the code table, the users.phone column and the gateway's recipient — so a
// number that normalises two ways is a person with two accounts.

func TestNormaliseTurnsWhatWasTypedIntoOneCanonicalNumber(t *testing.T) {
	for _, c := range []struct {
		name string
		raw  string
		dial string
		want string
	}{
		{"national Iranian with its trunk zero", "0912 123 4567", "98", "+989121234567"},
		{"the same number without the zero", "9121234567", "98", "+989121234567"},
		{"already carrying its own calling code", "989121234567", "98", "+989121234567"},
		{"written the international way", "+98 912 123 4567", "98", "+989121234567"},
		{"the old 00 prefix", "00989121234567", "98", "+989121234567"},
		{"punctuation and spaces", "(0912) 123-4567", "98", "+989121234567"},
		{"eastern digits, as a Persian keyboard produces them", "۰۹۱۲۱۲۳۴۵۶۷", "98", "+989121234567"},
		{"arabic-indic digits", "٠٩١٢١٢٣٤٥٦٧", "98", "+989121234567"},

		// The country is the point of the selector: the same digits mean
		// different people in different countries.
		{"an Omani number with Oman selected", "9123 4567", "968", "+96891234567"},
		{"a British number with its trunk zero", "07700 900123", "44", "+447700900123"},
		{"a German number", "0151 23456789", "49", "+4915123456789"},
		{"a US number, where there is no trunk zero to drop", "4155550123", "1", "+14155550123"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := Normalise(c.raw, c.dial)
			if !ok {
				t.Fatalf("Normalise(%q, %q) refused a usable number", c.raw, c.dial)
			}
			if got != c.want {
				t.Fatalf("Normalise(%q, %q) = %q, want %q", c.raw, c.dial, got, c.want)
			}
		})
	}
}

func TestAnInternationalNumberIsNotReadAsTheSelectedCountry(t *testing.T) {
	// Whether the number was written international has to be decided before the
	// punctuation is stripped: "+968…" and "968…" are identical afterwards, and
	// prefixing the selected country onto the first turns an Omani mobile into a
	// nonexistent Iranian one — a code sent somewhere the visitor cannot read.
	got, ok := Normalise("+968 9123 4567", "98")
	if !ok {
		t.Fatal("a number written in full international form was refused")
	}
	if got != "+96891234567" {
		t.Fatalf("got %q, want the Omani number left alone", got)
	}
}

// A number that merely begins with its own calling code is not the same as one
// that carries it. Oman's mobiles are eight digits and its code is 968, so an
// Omani who types 96812345 has typed a whole subscriber number — reading the
// leading 968 as a calling code leaves five digits addressed to nobody, and the
// gateway reports the send as fine.
func TestANumberThatMerelyStartsWithItsDialCodeIsStillANationalNumber(t *testing.T) {
	for _, c := range []struct {
		name string
		raw  string
		dial string
		want string
	}{
		{"Oman, the ecosystem's home market", "96812345", "968", "+96896812345"},
		{"Kuwait", "96512345", "965", "+96596512345"},
		{"Iran, where 98 can also open a subscriber number", "9812345678", "98", "+989812345678"},

		// The other direction still has to work: a number written with its
		// calling code and no '+' is left alone.
		{"an Omani number written with its code", "96892123456", "968", "+96892123456"},
		{"an Iranian number written with its code", "989121234567", "98", "+989121234567"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := Normalise(c.raw, c.dial)
			if !ok {
				t.Fatalf("Normalise(%q, %q) refused a usable number", c.raw, c.dial)
			}
			if got != c.want {
				t.Fatalf("Normalise(%q, %q) = %q, want %q", c.raw, c.dial, got, c.want)
			}
		})
	}
}

// The trunk prefix is not '0' everywhere, and a table that pretends it is
// deletes a real digit from a North American number and keeps one that is not
// part of a Russian one.
func TestTheTrunkPrefixIsTheOneTheCountryActuallyUses(t *testing.T) {
	if got, ok := Normalise("0415 555 0123", "1"); !ok || got != "+104155550123" {
		t.Fatalf("Normalise(+1 with a leading zero) = %q (%v); the +1 plan has no trunk zero to drop", got, ok)
	}
	if got, ok := Normalise("89123456789", "7"); !ok || got != "+79123456789" {
		t.Fatalf("Normalise(+7 national) = %q (%v); the +7 plan's trunk prefix is 8", got, ok)
	}
}

func TestNothingUsableIsRefusedRatherThanInvented(t *testing.T) {
	for _, raw := range []string{"", "   ", "abc", "+", "12", "0912", "091212345678901234"} {
		if got, ok := Normalise(raw, "98"); ok {
			t.Fatalf("Normalise(%q) produced %q; a number nobody can receive a code on must be refused at the form", raw, got)
		}
	}
}

func TestIranianDecidesWhichRouteCanCarryTheMessage(t *testing.T) {
	// The gateway's one-time-code route is declared for Iranian numbers only, so
	// this answer chooses between a templated domestic send and plain text
	// abroad. Getting it wrong means the message is refused before any provider
	// is tried.
	if !Iranian("+989121234567") {
		t.Fatal("an Iranian number was not recognised as one")
	}
	for _, foreign := range []string{"+96891234567", "+447700900123", "+14155550123", ""} {
		if Iranian(foreign) {
			t.Fatalf("%q was taken for an Iranian number and would go out on a route that refuses it", foreign)
		}
	}
}
