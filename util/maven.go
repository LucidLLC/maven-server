package util

import "encoding/xml"

type ArtifactMetadata struct {
	XMLName    xml.Name `xml:"metadata"`
	Text       string   `xml:",chardata"`
	GroupId    string   `xml:"groupId"`
	ArtifactId string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	Versioning struct {
		Text     string `xml:",chardata"`
		Latest   string `xml:"latest"`
		Release  string `xml:"release"`
		Versions struct {
			Text    string   `xml:",chardata"`
			Version []string `xml:"version"`
		} `xml:"versions"`
		Snapshot struct {
			Text        string `xml:",chardata"`
			Timestamp   string `xml:"timestamp"`
			BuildNumber string `xml:"buildNumber"`
		} `xml:"snapshot"`
		LastUpdated      string `xml:"lastUpdated"`
		SnapshotVersions struct {
			Text            string `xml:",chardata"`
			SnapshotVersion []struct {
				Text      string `xml:",chardata"`
				Extension string `xml:"extension"`
				Value     string `xml:"value"`
				Updated   string `xml:"updated"`
			} `xml:"snapshotVersion"`
		} `xml:"snapshotVersions"`
	} `xml:"versioning"`
}
