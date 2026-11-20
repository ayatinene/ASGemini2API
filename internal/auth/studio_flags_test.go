package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStablePackagedLoginFlags(t *testing.T) {
	for _, tc := range []struct {
		oneP, fst string
		want      StudioFlags
	}{
		{"COMPLETE:2025", "COMPLETE:2026", StudioFlags{Use1P: true, UseFST: true}},
		{"COMPLETE:2025", "PREVIEW", StudioFlags{Use1P: true}},
		{"INTERNAL", "COMPLETE:2026", StudioFlags{UseFST: true}},
		{"PREVIEW", "INTERNAL", StudioFlags{}},
	} {
		got, err := stableStudioFlags(useFSTFlag + "=" + tc.fst + " # example\n" + use1PFlag + " = " + tc.oneP + "\n")
		if err != nil || got != tc.want {
			t.Fatalf("flags %q/%q = %+v, %v; want %+v", tc.oneP, tc.fst, got, err, tc.want)
		}
	}
	for _, raw := range []string{
		use1PFlag + "=COMPLETE",
		use1PFlag + "=COMPLETE\n" + useFSTFlag + "=UNKNOWN",
		use1PFlag + "=COMPLETE\n" + useFSTFlag + "=COMPLETE\n" + useFSTFlag + "=PREVIEW",
	} {
		_, err := stableStudioFlags(raw)
		assertAuthCode(t, err, "incompatible_artifact")
	}
}

func TestInspectStudioRequiresPinnedArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "android-common.jar")
	_, err := InspectStudioPackage(path)
	assertAuthCode(t, err, "missing_artifact")
	if err := os.WriteFile(path, []byte("not the Studio JAR"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = InspectStudioPackage(path)
	assertAuthCode(t, err, "unpinned_artifact")
}
