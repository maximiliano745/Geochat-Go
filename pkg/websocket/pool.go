package websocket

import "fmt"

type Pool struct {
	Register   chan *Client
	Unregister chan *Client
	Clients    map[*Client]bool
	Broadcast  chan Message
}

func NewPool() *Pool {
	return &Pool{
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
		Clients:    make(map[*Client]bool),
		Broadcast:  make(chan Message),
	}
}

func (pool *Pool) Start() {
	for {
		select {
		case client := <-pool.Register:
			pool.Clients[client] = true
			fmt.Println("")
			fmt.Println("Tamaño del grupo de conexiones: ", len(pool.Clients))
			fmt.Println("")
			for client := range pool.Clients {
				fmt.Println("")
				fmt.Println(client)
				fmt.Println("")
				client.Conn.WriteJSON(Message{Type: 1, Body: "Nuevo usuario unido ..."})
			}
			break
		case client := <-pool.Unregister:
			delete(pool.Clients, client)
			fmt.Println("Tamaño del grupo de conexiones: ", len(pool.Clients))
			for client := range pool.Clients {
				client.Conn.WriteJSON(Message{Type: 1, Body: "Usuario Desconectado..."})
			}
			break
		case message := <-pool.Broadcast:
			fmt.Println("")
			fmt.Println("Envío de mensaje a todos los clientes en Pool")
			fmt.Println("")
			for client := range pool.Clients {
				if err := client.Conn.WriteJSON(message); err != nil {
					fmt.Println(err)
					return
				}
			}
		}
	}
}
