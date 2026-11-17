
class SortingAlgorithms:

    # HIGH first, then MEDIUM, then LOW
    @staticmethod
    def priority(incident):
        order = {
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3
        }
        return order.get(incident["severity"], 4)

    # 1. Bubble Sort
    @staticmethod
    def bubble_sort(data):
        arr = data.copy()
        n = len(arr)

        for i in range(n):
            for j in range(0, n - i - 1):

                if SortingAlgorithms.priority(arr[j]) > SortingAlgorithms.priority(arr[j + 1]):
                    arr[j], arr[j + 1] = arr[j + 1], arr[j]

        return arr

    # 2. Insertion Sort
    @staticmethod
    def insertion_sort(data):
        arr = data.copy()

        for i in range(1, len(arr)):
            current = arr[i]
            j = i - 1

            while j >= 0 and SortingAlgorithms.priority(arr[j]) > SortingAlgorithms.priority(current):
                arr[j + 1] = arr[j]
                j -= 1

            arr[j + 1] = current

        return arr

    # 3. Merge Sort
    @staticmethod
    def merge_sort(data):
        arr = data.copy()

        if len(arr) <= 1:
            return arr

        middle = len(arr) // 2

        left = SortingAlgorithms.merge_sort(arr[:middle])
        right = SortingAlgorithms.merge_sort(arr[middle:])

        return SortingAlgorithms.merge(left, right)

    @staticmethod
    def merge(left, right):
        result = []
        i = 0
        j = 0

        while i < len(left) and j < len(right):

            if SortingAlgorithms.priority(left[i]) <= SortingAlgorithms.priority(right[j]):
                result.append(left[i])
                i += 1
            else:
                result.append(right[j])
                j += 1

        result.extend(left[i:])
        result.extend(right[j:])

        return result

    # 4. Shell Sort
    @staticmethod
    def shell_sort(data):
        arr = data.copy()
        n = len(arr)
        gap = n // 2

        while gap > 0:

            for i in range(gap, n):
                current = arr[i]
                j = i

                while (
                    j >= gap
                    and SortingAlgorithms.priority(arr[j - gap])
                    > SortingAlgorithms.priority(current)
                ):
                    arr[j] = arr[j - gap]
                    j -= gap

                arr[j] = current

            gap //= 2

        return arr

    # 5. Heap Sort
    
    # 5. Heap Sort
    @staticmethod
    def heap_sort(data):
        arr = data.copy()
        n = len(arr)

        def heapify(size, root):
            largest = root
            left = 2 * root + 1
            right = 2 * root + 2

            if (
                left < size
                and SortingAlgorithms.priority(arr[left])
                > SortingAlgorithms.priority(arr[largest])
            ):
                largest = left

            if (
                right < size
                and SortingAlgorithms.priority(arr[right])
                > SortingAlgorithms.priority(arr[largest])
            ):
                largest = right

            if largest != root:
                arr[root], arr[largest] = arr[largest], arr[root]
                heapify(size, largest)

        # Build max heap
        for i in range(n // 2 - 1, -1, -1):
            heapify(n, i)

        # Extract elements
        for i in range(n - 1, 0, -1):
            arr[0], arr[i] = arr[i], arr[0]
            heapify(i, 0)

        return arr

