package appleversion

import (
	"debug/macho"
	"fmt"
)

// SectionVersion accepts only a bounded section contained by its read-only segment.
func SectionVersion(f *macho.File, fileSize uint64) (string, error) {
	var data []byte
	for _, s := range f.Sections {
		if s.Seg != "__TEXT" || s.Name != "__rodata" {
			continue
		}
		if data != nil || s.Size > MaxSection {
			return "", fmt.Errorf("invalid record section")
		}
		seg := f.Segment(s.Seg)
		off := uint64(s.Offset)
		if seg == nil || seg.Prot&2 != 0 || off > fileSize || s.Size > fileSize-off || off < seg.Offset || off-seg.Offset > seg.Filesz || s.Size > seg.Filesz-(off-seg.Offset) || s.Addr < seg.Addr || s.Addr-seg.Addr > seg.Memsz || s.Size > seg.Memsz-(s.Addr-seg.Addr) {
			return "", fmt.Errorf("invalid read-only record placement")
		}
		var err error
		data, err = s.Data()
		if err != nil {
			return "", err
		}
	}
	return Parse(data)
}
