package winres

import (
	"cmp"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// Resource type IDs.
const (
	TypeIcon      = 3  // RT_ICON
	TypeGroupIcon = 14 // RT_GROUP_ICON
	TypeVersion   = 16 // RT_VERSION
)

// IconGroupID is the resource ID of the application icon group, and
// VersionID the ID of the VERSIONINFO resource.
const (
	IconGroupID = 1
	VersionID   = 1
)

// Language is the language ID of every resource written by Object.
const Language = langEnglishUS

// Resource is one resource leaf in a PE resource directory.
type Resource struct {
	Type, ID, Language uint16
	Data               []byte
}

// Object returns a COFF object for GOOS=windows and the given GOARCH
// ("amd64" or "arm64") with the icon from ico and a VERSIONINFO for version.
// version is a semantic version without a "v" prefix, or empty for a
// development build. The output is deterministic.
func Object(goarch string, ico []byte, version string) ([]byte, error) {
	images, err := ParseICO(ico)
	if err != nil {
		return nil, err
	}
	v, err := ParseVersion(version)
	if err != nil {
		return nil, err
	}
	var resources []Resource
	group := binary.LittleEndian.AppendUint16(nil, 0)
	group = binary.LittleEndian.AppendUint16(group, 1)
	group = binary.LittleEndian.AppendUint16(group, uint16(len(images)))
	for i, image := range images {
		id := uint16(i + 1)
		group = append(group, dimensionByte(image.Width), dimensionByte(image.Height), image.ColorCount, 0)
		group = binary.LittleEndian.AppendUint16(group, image.Planes)
		group = binary.LittleEndian.AppendUint16(group, image.BitCount)
		group = binary.LittleEndian.AppendUint32(group, uint32(len(image.Data)))
		group = binary.LittleEndian.AppendUint16(group, id)
		resources = append(resources, Resource{TypeIcon, id, Language, image.Data})
	}
	resources = append(resources,
		Resource{TypeGroupIcon, IconGroupID, Language, group},
		Resource{TypeVersion, VersionID, Language, versionInfo(v)},
	)
	return coffObject(goarch, resources)
}

// COFF relocation types for a 32-bit image-relative address (ADDR32NB).
var relocations = map[string]struct {
	machine uint16
	reloc   uint16
}{
	"amd64": {pe.IMAGE_FILE_MACHINE_AMD64, 0x3}, // IMAGE_REL_AMD64_ADDR32NB
	"arm64": {pe.IMAGE_FILE_MACHINE_ARM64, 0x2}, // IMAGE_REL_ARM64_ADDR32NB
}

const (
	coffHeaderSize    = 20
	sectionHeaderSize = 40
	relocationSize    = 10
	symbolSize        = 18
	dirSize           = 16
	dirEntrySize      = 8
	dataEntrySize     = 16
	subdirectoryFlag  = 0x80000000
)

// coffObject lays out a single .rsrc section holding the resource tree and
// returns it as a relocatable COFF object. Each data entry's OffsetToData
// holds the section offset of its data and is relocated against the section
// symbol, so the linker turns it into an RVA.
func coffObject(goarch string, resources []Resource) ([]byte, error) {
	target, ok := relocations[goarch]
	if !ok {
		return nil, fmt.Errorf("unsupported windows architecture %q", goarch)
	}
	section, relocs, err := resourceSection(resources)
	if err != nil {
		return nil, err
	}
	dataOffset := coffHeaderSize + sectionHeaderSize
	relocOffset := dataOffset + len(section)
	symbolOffset := relocOffset + relocationSize*len(relocs)
	if len(relocs) > 0xFFFF {
		return nil, errors.New("too many resources")
	}

	b := make([]byte, 0, symbolOffset+symbolSize+4)
	b = binary.LittleEndian.AppendUint16(b, target.machine)
	b = binary.LittleEndian.AppendUint16(b, 1) // NumberOfSections
	b = binary.LittleEndian.AppendUint32(b, 0) // TimeDateStamp
	b = binary.LittleEndian.AppendUint32(b, uint32(symbolOffset))
	b = binary.LittleEndian.AppendUint32(b, 1) // NumberOfSymbols
	b = binary.LittleEndian.AppendUint16(b, 0) // SizeOfOptionalHeader
	b = binary.LittleEndian.AppendUint16(b, 0) // Characteristics

	b = append(b, ".rsrc\x00\x00\x00"...)
	b = binary.LittleEndian.AppendUint32(b, 0) // VirtualSize
	b = binary.LittleEndian.AppendUint32(b, 0) // VirtualAddress
	b = binary.LittleEndian.AppendUint32(b, uint32(len(section)))
	b = binary.LittleEndian.AppendUint32(b, uint32(dataOffset))
	b = binary.LittleEndian.AppendUint32(b, uint32(relocOffset))
	b = binary.LittleEndian.AppendUint32(b, 0) // PointerToLinenumbers
	b = binary.LittleEndian.AppendUint16(b, uint16(len(relocs)))
	b = binary.LittleEndian.AppendUint16(b, 0) // NumberOfLinenumbers
	b = binary.LittleEndian.AppendUint32(b, pe.IMAGE_SCN_CNT_INITIALIZED_DATA|pe.IMAGE_SCN_MEM_READ)

	b = append(b, section...)
	for _, offset := range relocs {
		b = binary.LittleEndian.AppendUint32(b, offset)
		b = binary.LittleEndian.AppendUint32(b, 0) // symbol 0: the .rsrc section symbol
		b = binary.LittleEndian.AppendUint16(b, target.reloc)
	}

	b = append(b, ".rsrc\x00\x00\x00"...)
	b = binary.LittleEndian.AppendUint32(b, 0) // Value
	b = binary.LittleEndian.AppendUint16(b, 1) // SectionNumber
	b = binary.LittleEndian.AppendUint16(b, 0) // Type
	b = append(b, 3, 0)                        // IMAGE_SYM_CLASS_STATIC, no aux symbols
	b = binary.LittleEndian.AppendUint32(b, 4) // empty string table
	return b, nil
}

// resourceSection encodes the three-level resource directory (type, ID,
// language) followed by the data entries and the 8-byte aligned data. It
// returns the section and the offsets of the fields that need relocation.
func resourceSection(resources []Resource) ([]byte, []uint32, error) {
	resources = slices.Clone(resources)
	slices.SortStableFunc(resources, func(a, b Resource) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Language, b.Language))
	})
	for i := 1; i < len(resources); i++ {
		a, b := resources[i-1], resources[i]
		if a.Type == b.Type && a.ID == b.ID && a.Language == b.Language {
			return nil, nil, fmt.Errorf("duplicate resource type %d ID %d language %#x", a.Type, a.ID, a.Language)
		}
	}
	type group struct {
		key   uint16
		items []Resource
	}
	groupBy := func(items []Resource, key func(Resource) uint16) []group {
		var groups []group
		for _, r := range items {
			if len(groups) == 0 || groups[len(groups)-1].key != key(r) {
				groups = append(groups, group{key: key(r)})
			}
			groups[len(groups)-1].items = append(groups[len(groups)-1].items, r)
		}
		return groups
	}

	types := groupBy(resources, func(r Resource) uint16 { return r.Type })
	idsByType := make([][]group, len(types))
	for i, t := range types {
		idsByType[i] = groupBy(t.items, func(r Resource) uint16 { return r.ID })
	}

	// Offsets of every directory, in the order written.
	offset := dirSize + dirEntrySize*len(types)
	typeDirs := make([]int, len(types))
	for i := range types {
		typeDirs[i] = offset
		offset += dirSize + dirEntrySize*len(idsByType[i])
	}
	langDirs := make([][]int, len(types))
	for i, ids := range idsByType {
		for _, id := range ids {
			langDirs[i] = append(langDirs[i], offset)
			offset += dirSize + dirEntrySize*len(id.items)
		}
	}
	dataEntries := offset
	offset += dataEntrySize * len(resources)
	dataOffsets := make([]int, len(resources))
	for i, r := range resources {
		offset = (offset + 7) &^ 7
		dataOffsets[i] = offset
		offset += len(r.Data)
	}
	size := (offset + 7) &^ 7

	b := make([]byte, size)
	directory := func(at int, entries [][2]uint32) {
		binary.LittleEndian.PutUint16(b[at+14:], uint16(len(entries))) // NumberOfIdEntries
		for i, e := range entries {
			binary.LittleEndian.PutUint32(b[at+dirSize+dirEntrySize*i:], e[0])
			binary.LittleEndian.PutUint32(b[at+dirSize+dirEntrySize*i+4:], e[1])
		}
	}
	var rootEntries [][2]uint32
	leaf := 0
	var relocs []uint32
	for i, t := range types {
		rootEntries = append(rootEntries, [2]uint32{uint32(t.key), subdirectoryFlag | uint32(typeDirs[i])})
		var idEntries [][2]uint32
		for j, id := range idsByType[i] {
			idEntries = append(idEntries, [2]uint32{uint32(id.key), subdirectoryFlag | uint32(langDirs[i][j])})
			var langEntries [][2]uint32
			for _, r := range id.items {
				entry := dataEntries + dataEntrySize*leaf
				langEntries = append(langEntries, [2]uint32{uint32(r.Language), uint32(entry)})
				binary.LittleEndian.PutUint32(b[entry:], uint32(dataOffsets[leaf]))
				binary.LittleEndian.PutUint32(b[entry+4:], uint32(len(r.Data)))
				copy(b[dataOffsets[leaf]:], r.Data)
				relocs = append(relocs, uint32(entry))
				leaf++
			}
			directory(langDirs[i][j], langEntries)
		}
		directory(typeDirs[i], idEntries)
	}
	directory(0, rootEntries)
	return b, relocs, nil
}

// Read returns every resource leaf of a linked PE image, in directory order.
// Only numeric type, name and language IDs are supported.
func Read(f *pe.File) ([]Resource, error) {
	var dir pe.DataDirectory
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if h.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_RESOURCE {
			dir = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
		}
	case *pe.OptionalHeader32:
		if h.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_RESOURCE {
			dir = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
		}
	default:
		return nil, errors.New("PE: missing optional header")
	}
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil, errors.New("PE: no resource directory")
	}
	var section *pe.Section
	for _, s := range f.Sections {
		if dir.VirtualAddress >= s.VirtualAddress && dir.VirtualAddress < s.VirtualAddress+max(s.VirtualSize, s.Size) {
			section = s
			break
		}
	}
	if section == nil {
		return nil, errors.New("PE: resource directory is outside every section")
	}
	data, err := section.Data()
	if err != nil {
		return nil, err
	}
	base := dir.VirtualAddress - section.VirtualAddress
	if uint64(base) >= uint64(len(data)) {
		return nil, errors.New("PE: resource directory is outside its section")
	}
	r := reader{data: data[base:], sectionRVA: section.VirtualAddress, section: data}
	var out []Resource
	err = r.walk(0, 0, nil, &out)
	return out, err
}

type reader struct {
	data       []byte // resource directory and everything after it
	sectionRVA uint32
	section    []byte
	visited    int
}

func (r *reader) walk(offset uint32, depth int, path []uint16, out *[]Resource) error {
	r.visited++
	if r.visited > 1<<16 {
		return errors.New("PE: resource directory is too large")
	}
	if uint64(offset)+dirSize > uint64(len(r.data)) {
		return errors.New("PE: resource directory out of range")
	}
	named := int(binary.LittleEndian.Uint16(r.data[offset+12:]))
	ids := int(binary.LittleEndian.Uint16(r.data[offset+14:]))
	for i := range named + ids {
		at := uint64(offset) + dirSize + uint64(dirEntrySize*i)
		if at+dirEntrySize > uint64(len(r.data)) {
			return errors.New("PE: resource directory entry out of range")
		}
		name := binary.LittleEndian.Uint32(r.data[at:])
		target := binary.LittleEndian.Uint32(r.data[at+4:])
		if name&subdirectoryFlag != 0 || name > 0xFFFF {
			return errors.New("PE: named resources are not supported")
		}
		next := append(slices.Clone(path), uint16(name))
		if target&subdirectoryFlag != 0 {
			if depth >= 2 {
				return errors.New("PE: resource directory is deeper than three levels")
			}
			if err := r.walk(target&^subdirectoryFlag, depth+1, next, out); err != nil {
				return err
			}
			continue
		}
		if depth != 2 {
			return errors.New("PE: resource data entry above the language level")
		}
		if uint64(target)+dataEntrySize > uint64(len(r.data)) {
			return errors.New("PE: resource data entry out of range")
		}
		rva := binary.LittleEndian.Uint32(r.data[target:])
		size := binary.LittleEndian.Uint32(r.data[target+4:])
		start := uint64(rva) - uint64(r.sectionRVA)
		if rva < r.sectionRVA || start+uint64(size) > uint64(len(r.section)) {
			return fmt.Errorf("PE: resource %v data out of range", next)
		}
		*out = append(*out, Resource{Type: next[0], ID: next[1], Language: next[2], Data: r.section[start : start+uint64(size)]})
	}
	return nil
}

// Icons returns the images of the icon group id, in group order, with their
// data taken from the RT_ICON resources.
func Icons(resources []Resource, id uint16) ([]Image, error) {
	find := func(typ, id uint16) []byte {
		for _, r := range resources {
			if r.Type == typ && r.ID == id {
				return r.Data
			}
		}
		return nil
	}
	group := find(TypeGroupIcon, id)
	if len(group) < 6 || binary.LittleEndian.Uint16(group) != 0 || binary.LittleEndian.Uint16(group[2:]) != 1 {
		return nil, fmt.Errorf("icon group %d is missing or invalid", id)
	}
	count := int(binary.LittleEndian.Uint16(group[4:]))
	if len(group) != 6+14*count || count == 0 {
		return nil, fmt.Errorf("icon group %d has a bad length", id)
	}
	images := make([]Image, 0, count)
	for i := range count {
		e := group[6+14*i:]
		iconID := binary.LittleEndian.Uint16(e[12:])
		data := find(TypeIcon, iconID)
		if data == nil {
			return nil, fmt.Errorf("icon group %d refers to missing icon %d", id, iconID)
		}
		if uint32(len(data)) != binary.LittleEndian.Uint32(e[8:]) {
			return nil, fmt.Errorf("icon %d size differs from its group entry", iconID)
		}
		images = append(images, Image{
			Width:      dimension(e[0]),
			Height:     dimension(e[1]),
			ColorCount: e[2],
			Planes:     binary.LittleEndian.Uint16(e[4:]),
			BitCount:   binary.LittleEndian.Uint16(e[6:]),
			Data:       data,
		})
	}
	return images, nil
}
