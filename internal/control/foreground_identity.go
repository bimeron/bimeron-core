package control

// ProcessIdentity is checked using OS handles, never trusted from a handshake.
type ProcessIdentity struct {
	ImageVolume uint32 `json:"image_volume"`
	ImageIndex  uint64 `json:"image_index,string"`
	PID         uint32 `json:"pid"`
	Created     uint64 `json:"created,string"`
	SID         string `json:"sid"`
	Session     uint32 `json:"session"`
	ImageSHA256 string `json:"image_sha256"`
	Elevated    bool   `json:"elevated"`
}

func matchingForegroundPeer(owner, expected, peer ProcessIdentity) bool {
	return peer.SID == owner.SID && peer.Session == owner.Session && peer.ImageSHA256 != "" && peer.ImageSHA256 == expected.ImageSHA256 && peer.ImageVolume == expected.ImageVolume && peer.ImageIndex == expected.ImageIndex
}
