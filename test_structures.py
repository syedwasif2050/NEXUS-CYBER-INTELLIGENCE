from modules.data_structures import (
    Queue,
    Stack,
    SinglyLinkedList,
    DoublyLinkedList
)

# Queue Test
q = Queue()
q.enqueue("Login Failed")
q.enqueue("Login Success")

print("Queue:", q.dequeue())

# Stack Test
s = Stack()
s.push("Event 1")
s.push("Event 2")

print("Stack:", s.pop())

# Singly Linked List Test
sll = SinglyLinkedList()
sll.insert("Event A")
sll.insert("Event B")

print("Singly Linked List:", sll.display())

# Doubly Linked List Test
dll = DoublyLinkedList()
dll.insert("Incident 1")
dll.insert("Incident 2")

print("Doubly Forward:", dll.display_forward())
print("Doubly Backward:", dll.display_backward())