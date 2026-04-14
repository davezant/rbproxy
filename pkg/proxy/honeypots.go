package proxy

type FakeHandler func(req RequestPacket) ResponsePacket

type FakePath struct {
    Path    string
    Handler FakeHandler
}

func ChangeHeaders() {

}


