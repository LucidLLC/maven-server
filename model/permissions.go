package model

const (
	// User can manage and update permissions
	ManagePermissionsFlag = 1 << 1
	// User can manage accounts (create & delete accounts)
	ManageAccountsFlag = 1 << 2
	// User can view the accounts available to them
	ViewAccountsFlag = 1 << 3

	// User can upload artifacts
	UploadArtifactsFlag = 1 << 4

	// User can delete artifacts
	DeleteArtifactsFlag = 1 << 5

	// User can create, delete and view groups
	ManageGroupsFlag = 1 << 6

	ViewGroupsFlag = 1 << 7

	TeamOwnerFlag = 1 << 8
)

const (
	IdentityScope = "maven:identity"
)

type Permissible interface {
	HasPermission(int) bool
	TogglePermission(int)
}
