package marionette

import "testing"

func TestProfileByName(t *testing.T) {
	if p := ProfileByName("telegram"); p == nil {
		t.Fatal("telegram profile missing")
	}
	if p := ProfileByName("  VK  "); p == nil {
		t.Fatal("vk lookup must be case- and space-insensitive")
	}
	if p := ProfileByName("doesnotexist"); p != nil {
		t.Fatal("unknown profile should return nil")
	}
}

func TestKnownProfilesSorted(t *testing.T) {
	names := KnownProfiles()
	if len(names) == 0 {
		t.Fatal("expected at least one profile")
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("KnownProfiles must be sorted: %q >= %q", names[i-1], names[i])
		}
	}
}
