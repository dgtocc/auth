package auth

import (
	"log"
	"os"
	"testing"
)

func MustMany(errs ...error) (err error) {
	for _, v := range errs {
		if v != nil {
			err = v
			return
		}
	}
	return err
}

func TestMain(m *testing.M) {
	log.Printf("Starting TestMain")
	os.Remove("test.db")
	code := m.Run()
	log.Printf("Finishing TestMain")
	os.Exit(code)
}

func TestInit(t *testing.T) {
	err := Init(&Config{
		Dburl:    "test.db",
		Dbdriver: "sqlite",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPrepare(t *testing.T) {
	err := Prepare()
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoginRoot(t *testing.T) {

	sid, err := Auth("root", "toor")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := Sess(sid)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", sess)
}

func TestAddData(t *testing.T) {
	ptrtrue := true
	u := &User{
		Username: "usera",
		Enabled:  &ptrtrue,
		Name:     "User A",
		Email:    "mail@mail.com",
		Hash:     "",
	}

	err := MustMany(
		AddUser(u),
		AddGroup("groupa"),
		AddPerm("perma"),
		AddPermToGroup("groupa", "perma"),
		AddUserToGroup("usera", "groupa"),
		SetUserPass("usera", "usera123"),
	)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := Auth("usera", "usera123")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := Sess(sid)
	if err != nil {
		t.Fatal(err)
	}
	check := sess.HasPerm("perma")
	if !check {
		t.Fatal("perma not found for usera")
	}

}

func TestAddRemoveGroup(t *testing.T) {
	ptrtrue := true
	u := &User{
		Username: "usera2",
		Enabled:  &ptrtrue,
		Name:     "User A2",
		Email:    "mail@mail.com",
		Hash:     "",
	}

	err := MustMany(
		AddUser(u),
		AddGroup("groupa2"),
		AddPerm("perma2"),
		AddPermToGroup("groupa2", "perma2"),
		AddUserToGroup("usera2", "groupa2"),
		AddGroup("groupb2"),
		AddPerm("permb2"),
		AddPermToGroup("groupb2", "permb2"),
		AddUserToGroup("usera2", "groupb2"),
		SetUserPass("usera2", "usera123"),
	)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := Auth("usera2", "usera123")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := Sess(sid)
	if err != nil {
		t.Fatal(err)
	}
	check := sess.HasPerm("permb2")
	if !check {
		t.Fatal("permb2 not found for usera2")
	}

	err = MustMany(
		RemoveUserFromGroup("usera2", "groupb2"),
	)
	if err != nil {
		t.Fatal(err)
	}
	sid, err = Auth("usera2", "usera123")
	if err != nil {
		t.Fatal(err)
	}
	sess, err = Sess(sid)
	if err != nil {
		t.Fatal(err)
	}
	check = sess.HasPerm("permb2")
	if check {
		t.Fatal("permb2 should not have been found for usera2")
	}

}
