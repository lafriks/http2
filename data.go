package http2

import (
	"github.com/lafriks/http2/http2utils"
)

const FrameData FrameType = 0x0

var _ Frame = &Data{}

// Data defines a FrameData
//
// Data frames can have the following flags:
// END_STREAM
// PADDED
//
// https://tools.ietf.org/html/rfc7540#section-6.1
type Data struct {
	endStream  bool
	hasPadding bool
	b          []byte // owned data bytes (the send path copies into it)
	// view aliases the frame header's payload on the receive path
	// (Deserialize), skipping a copy
	view []byte
}

func (data *Data) Type() FrameType {
	return FrameData
}

func (data *Data) Reset() {
	data.endStream = false
	data.hasPadding = false
	data.b = data.b[:0]
	data.view = nil
}

// CopyTo copies data to d.
func (data *Data) CopyTo(d *Data) {
	d.hasPadding = data.hasPadding
	d.endStream = data.endStream
	d.b = append(d.b[:0], data.Data()...)
	d.view = nil
}

func (data *Data) SetEndStream(value bool) {
	data.endStream = value
}

func (data *Data) EndStream() bool {
	return data.endStream
}

// Data returns the byte slice of the data read/to be sendStream.
func (data *Data) Data() []byte {
	if data.view != nil {
		return data.view
	}

	return data.b
}

// SetData resets data byte slice and sets b.
func (data *Data) SetData(b []byte) {
	data.view = nil
	data.b = append(data.b[:0], b...)
}

// SetDataNoCopy points the frame at b without copying it.
func (data *Data) SetDataNoCopy(b []byte) {
	data.view = b
}

// Padding returns true if the data will be/was hasPaddingded.
func (data *Data) Padding() bool {
	return data.hasPadding
}

// SetPadding sets hasPaddingding to the data if true. If false the data won't be hasPaddingded.
func (data *Data) SetPadding(value bool) {
	data.hasPadding = value
}

// Append appends b to data.
func (data *Data) Append(b []byte) {
	if data.view != nil {
		// materialize the borrowed view before growing it
		data.b = append(data.b[:0], data.view...)
		data.view = nil
	}

	data.b = append(data.b, b...)
}

func (data *Data) Len() int {
	return len(data.Data())
}

// Write writes b to data.
func (data *Data) Write(b []byte) (int, error) {
	n := len(b)
	data.Append(b)

	return n, nil
}

func (data *Data) Deserialize(fr *FrameHeader) error {
	payload := fr.payload

	if fr.Flags().Has(FlagPadded) {
		var err error
		payload, err = http2utils.CutPadding(payload, fr.Len())
		if err != nil {
			return err
		}
	}

	data.endStream = fr.Flags().Has(FlagEndStream)
	data.view = payload

	return nil
}

func (data *Data) Serialize(fr *FrameHeader) {
	// TODO: generate hasPadding and set to the frame payload
	if data.endStream {
		fr.SetFlags(
			fr.Flags().Add(FlagEndStream))
	}

	if data.hasPadding {
		fr.SetFlags(
			fr.Flags().Add(FlagPadded))

		if data.view != nil {
			// materialize the borrowed view: padding mutates the buffer
			data.b = append(data.b[:0], data.view...)
			data.view = nil
		}

		data.b = http2utils.AddPadding(data.b)
	}

	fr.setPayloadNoCopy(data.Data())
}
