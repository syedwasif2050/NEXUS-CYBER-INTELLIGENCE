
# ==========================================
# SMART CYBER THREAT DETECTION SYSTEM
# File: data_structures.py
# ==========================================


# 1. QUEUE - FIFO (First In, First Out)

class Queue:

    def __init__(self):
        self.items = []

    def enqueue(self, item):
        self.items.append(item)

    def dequeue(self):
        if self.is_empty():
            return None

        return self.items.pop(0)

    def is_empty(self):
        return len(self.items) == 0

    def size(self):
        return len(self.items)


# 2. STACK - LIFO (Last In, First Out)

class Stack:

    def __init__(self):
        self.items = []

    def push(self, item):
        self.items.append(item)

    def pop(self):
        if self.is_empty():
            return None

        return self.items.pop()

    def peek(self):
        if self.is_empty():
            return None

        return self.items[-1]

    def is_empty(self):
        return len(self.items) == 0

    def size(self):
        return len(self.items)


# 3. SINGLY LINKED LIST

class Node:

    def __init__(self, data):
        self.data = data
        self.next = None


class SinglyLinkedList:

    def __init__(self):
        self.head = None

    def insert(self, data):

        new_node = Node(data)

        if self.head is None:
            self.head = new_node
            return

        current = self.head

        while current.next is not None:
            current = current.next

        current.next = new_node

    def display(self):

        current = self.head
        result = []

        while current is not None:
            result.append(current.data)
            current = current.next

        return result

    def size(self):

        count = 0
        current = self.head

        while current is not None:
            count += 1
            current = current.next

        return count


# 4. DOUBLY LINKED LIST

class DoublyNode:

    def __init__(self, data):
        self.data = data
        self.previous = None
        self.next = None


class DoublyLinkedList:

    def __init__(self):
        self.head = None
        self.tail = None

    def insert(self, data):

        new_node = DoublyNode(data)

        if self.head is None:
            self.head = new_node
            self.tail = new_node
            return

        new_node.previous = self.tail
        self.tail.next = new_node
        self.tail = new_node

    def display_forward(self):

        result = []
        current = self.head

        while current is not None:
            result.append(current.data)
            current = current.next

        return result

    def display_backward(self):

        result = []
        current = self.tail

        while current is not None:
            result.append(current.data)
            current = current.previous

        return result

    def size(self):

        count = 0
        current = self.head

        while current is not None:
            count += 1
            current = current.next

        return count
