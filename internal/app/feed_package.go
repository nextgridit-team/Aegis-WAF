package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"path"
	"strings"
)

const maxCataloguePackageBytes = 8 << 20
const maxPackedCatalogueRules = 2000

type cataloguePackage struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	RuleCount int    `json:"rule_count"`
	SizeBytes int64  `json:"size_bytes"`
}

// Check the central directory before archive/zip can allocate for its records.
// Packages use a single disk, no ZIP64, and only stored/deflated regular files.
func boundedZipDirectory(raw []byte, ruleCount int) error {
	end := -1
	for i := len(raw) - 22; i >= 0 && i >= len(raw)-65557; i-- {
		if binary.LittleEndian.Uint32(raw[i:i+4]) == 0x06054b50 && int(binary.LittleEndian.Uint16(raw[i+20:i+22])) == len(raw)-i-22 {
			end = i
			break
		}
	}
	if end < 0 {
		return invalid("invalid catalogue ZIP directory")
	}
	u16 := func(offset int) uint16 { return binary.LittleEndian.Uint16(raw[end+offset : end+offset+2]) }
	count := int(u16(10))
	if u16(4) != 0 || u16(6) != 0 || int(u16(8)) != count || count < ruleCount || count > ruleCount+2 || count > maxPackedCatalogueRules+2 {
		return invalid("catalogue ZIP entry count or disk format is unsupported")
	}
	start := uint64(binary.LittleEndian.Uint32(raw[end+16 : end+20]))
	size := uint64(binary.LittleEndian.Uint32(raw[end+12 : end+16]))
	if start+size != uint64(end) {
		return invalid("invalid catalogue ZIP directory bounds")
	}
	pos := int(start)
	total := uint64(0)
	for n := 0; n < count; n++ {
		if pos+46 > end || binary.LittleEndian.Uint32(raw[pos:pos+4]) != 0x02014b50 {
			return invalid("invalid catalogue ZIP entry")
		}
		flags := binary.LittleEndian.Uint16(raw[pos+8 : pos+10])
		method := binary.LittleEndian.Uint16(raw[pos+10 : pos+12])
		expanded := binary.LittleEndian.Uint32(raw[pos+24 : pos+28])
		name := int(binary.LittleEndian.Uint16(raw[pos+28 : pos+30]))
		extra := int(binary.LittleEndian.Uint16(raw[pos+30 : pos+32]))
		comment := int(binary.LittleEndian.Uint16(raw[pos+32 : pos+34]))
		if flags&1 != 0 || (method != zip.Store && method != zip.Deflate) || expanded > 64<<10 || name < 1 || name > 240 || binary.LittleEndian.Uint16(raw[pos+34:pos+36]) != 0 {
			return invalid("unsupported or oversized catalogue ZIP member")
		}
		total += uint64(expanded)
		if total > maxCataloguePackageBytes {
			return invalid("expanded catalogue exceeds 8 MiB")
		}
		pos += 46 + name + extra + comment
		if pos > end {
			return invalid("invalid catalogue ZIP member bounds")
		}
	}
	if pos != end {
		return invalid("catalogue ZIP directory count does not match contents")
	}
	return nil
}

func parseCataloguePackage(ctx context.Context, manifest ruleManifest, raw []byte) ([]catalogueCandidate, error) {
	descriptor := manifest.Package
	if descriptor == nil || len(raw) > maxCataloguePackageBytes || int64(len(raw)) != descriptor.SizeBytes {
		return nil, invalid("catalogue package size mismatch")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != descriptor.SHA256 {
		return nil, invalid("catalogue package checksum mismatch")
	}
	if e := boundedZipDirectory(raw, descriptor.RuleCount); e != nil {
		return nil, e
	}
	archive, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		return nil, invalid("invalid catalogue ZIP")
	}
	seenNames, seenIDs := map[string]bool{}, map[string]bool{}
	items := []catalogueCandidate{}
	total := 0
	for _, member := range archive.File {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if seenNames[member.Name] || !member.Mode().IsRegular() || member.UncompressedSize64 > 64<<10 {
			return nil, invalid("duplicate, nonregular or oversized package member")
		}
		seenNames[member.Name] = true
		license := member.Name == "LICENSE" || member.Name == "LICENSES/nuclei-templates.txt"
		if !license {
			if !strings.HasPrefix(member.Name, "rules/") || !strings.HasSuffix(member.Name, ".json") {
				return nil, invalid("package members must be rule JSON files or supported license notices")
			}
			for _, segment := range strings.Split(member.Name, "/") {
				if segment == "." || segment == ".." || !namedKey.MatchString(segment) {
					return nil, invalid("unsafe package member path")
				}
			}
		}
		reader, e := member.Open()
		if e != nil {
			return nil, invalid("catalogue member could not be opened")
		}
		content, readErr := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || len(content) > 64<<10 || uint64(len(content)) != member.UncompressedSize64 {
			return nil, invalid("catalogue member is truncated, corrupt or oversized")
		}
		total += len(content)
		if total > maxCataloguePackageBytes {
			return nil, invalid("expanded catalogue exceeds 8 MiB")
		}
		if license {
			continue
		}
		id := strings.TrimSuffix(path.Base(member.Name), ".json")
		if len(id) > 64 || !namedKey.MatchString(id) || seenIDs[id] {
			return nil, invalid("invalid or duplicate packaged rule ID")
		}
		seenIDs[id] = true
		hash := sha256.Sum256(content)
		sum := hex.EncodeToString(hash[:])
		file, e := parseCatalogueRule(content, manifestEntry{ID: id, SHA256: sum})
		if e != nil {
			return nil, e
		}
		items = append(items, catalogueCandidate{File: file, Digest: sum})
	}
	if len(items) != descriptor.RuleCount {
		return nil, invalid("catalogue package rule count mismatch")
	}
	return items, nil
}
