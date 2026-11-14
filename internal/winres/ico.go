// Package winres builds and reads the Windows PE resources of the Bimeron Core
// executable: the application icon and the VERSIONINFO block.
//
// Object produces a COFF object (.syso) that the Go linker merges into the
// .rsrc section of a windows/amd64 or windows/arm64 executable. Read walks
// the resource directory of a linked executable so release checks can verify
// the result independently of the build.
package winres

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Image is one image of an icon. Width and Height are in pixels; 256 is
// stored as 0 in ICO and group icon directories.
type Image struct {
	Width, Height int
	ColorCount    uint8
	Planes        uint16
	BitCount      uint16
	Data          []byte
}

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

// PNG reports whether the image data is PNG-compressed.
func (i Image) PNG() bool { return bytes.HasPrefix(i.Data, pngSignature) }

// ParseICO parses an ICO file into its images, in file order.
func ParseICO(data []byte) ([]Image, error) {
	if len(data) < 6 {
		return nil, errors.New("ICO: truncated header")
	}
	if binary.LittleEndian.Uint16(data[0:]) != 0 || binary.LittleEndian.Uint16(data[2:]) != 1 {
		return nil, errors.New("ICO: not an icon file")
	}
	count := int(binary.LittleEndian.Uint16(data[4:]))
	if count == 0 {
		return nil, errors.New("ICO: no images")
	}
	if len(data) < 6+16*count {
		return nil, errors.New("ICO: truncated directory")
	}
	images := make([]Image, 0, count)
	for i := range count {
		entry := data[6+16*i:]
		size := binary.LittleEndian.Uint32(entry[8:])
		offset := binary.LittleEndian.Uint32(entry[12:])
		if size == 0 || uint64(offset)+uint64(size) > uint64(len(data)) || offset < uint32(6+16*count) {
			return nil, fmt.Errorf("ICO: image %d is outside the file", i)
		}
		images = append(images, Image{
			Width:      dimension(entry[0]),
			Height:     dimension(entry[1]),
			ColorCount: entry[2],
			Planes:     binary.LittleEndian.Uint16(entry[4:]),
			BitCount:   binary.LittleEndian.Uint16(entry[6:]),
			Data:       data[offset : offset+size],
		})
	}
	return images, nil
}

func dimension(b byte) int {
	if b == 0 {
		return 256
	}
	return int(b)
}

func dimensionByte(n int) byte {
	if n == 256 {
		return 0
	}
	return byte(n)
}
