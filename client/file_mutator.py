#!/usr/bin/env python3
"""
File mutation utility for testing content-defined chunking and diff algorithms.

This script randomly mutates files by:
- Modifying bytes at random offsets
- Inserting new data at random positions
- Removing data ranges
- Adding pauses between operations for realistic synchronization testing
"""

import argparse
import os
import random
import time
from typing import Optional


def mutate_byte_range(
    file_path: str,
    offset: int,
    length: int,
    pause_between: float = 0.1
) -> None:
    """
    Mutate a range of bytes at the specified offset with random data.
    
    Args:
        file_path: Path to the file to mutate
        offset: Starting offset in bytes
        length: Number of bytes to mutate
        pause_between: Pause duration in seconds after mutation
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r+b') as f:
        file_size = os.path.getsize(file_path)
        
        # Validate offset and length
        if offset >= file_size:
            raise ValueError(f"Offset {offset} exceeds file size {file_size}")
        
        # Adjust length to not exceed file boundaries
        actual_length = min(length, file_size - offset)
        
        # Read current data
        f.seek(offset)
        original_data = f.read(actual_length)
        
        # Generate random mutation data
        mutation_data = bytes(random.getrandbits(8) for _ in range(actual_length))
        
        # Write mutation
        f.seek(offset)
        f.write(mutation_data)
        
        print(f"Mutated {actual_length} bytes at offset {offset}")
    
    time.sleep(pause_between)


def insert_data(
    file_path: str,
    offset: int,
    size: int,
    pause_between: float = 0.1
) -> None:
    """
    Insert random data at the specified offset.
    
    Args:
        file_path: Path to the file to mutate
        offset: Position to insert data at
        size: Number of bytes to insert
        pause_between: Pause duration in seconds after insertion
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r+b') as f:
        file_size = os.path.getsize(file_path)
        
        if offset > file_size:
            raise ValueError(f"Offset {offset} exceeds file size {file_size}")
        
        # Read from offset to end
        f.seek(offset)
        tail_data = f.read()
        
        # Generate random insertion data
        insert_data_bytes = bytes(random.getrandbits(8) for _ in range(size))
        
        # Write new data
        f.seek(offset)
        f.write(insert_data_bytes)
        f.write(tail_data)
    
    print(f"Inserted {size} bytes at offset {offset}")
    time.sleep(pause_between)


def remove_data(
    file_path: str,
    offset: int,
    size: int,
    pause_between: float = 0.1
) -> None:
    """
    Remove data at the specified offset and size.
    
    Args:
        file_path: Path to the file to mutate
        offset: Starting position of data to remove
        size: Number of bytes to remove
        pause_between: Pause duration in seconds after removal
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r+b') as f:
        file_size = os.path.getsize(file_path)
        
        if offset >= file_size:
            raise ValueError(f"Offset {offset} exceeds file size {file_size}")
        
        # Adjust size to not exceed file boundaries
        actual_size = min(size, file_size - offset)
        
        # Read data before and after the removal range
        f.seek(0)
        before_data = f.read(offset)
        f.seek(offset + actual_size)
        after_data = f.read()
        
        # Truncate and rewrite
        f.seek(0)
        f.write(before_data)
        f.write(after_data)
        f.truncate()
    
    print(f"Removed {actual_size} bytes at offset {offset}")
    time.sleep(pause_between)


def random_mutations(
    file_path: str,
    num_mutations: int = 10,
    pause_range: tuple = (0.1, 0.5),
    operation_mix: Optional[dict] = None
) -> None:
    """
    Apply random mutations to a file.
    
    Args:
        file_path: Path to the file to mutate
        num_mutations: Number of mutation operations to perform
        pause_range: Tuple of (min_pause, max_pause) in seconds
        operation_mix: Dict with 'mutate', 'insert', 'remove' probabilities
                      (defaults to equal distribution)
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if operation_mix is None:
        operation_mix = {'mutate': 0.5, 'insert': 0.25, 'remove': 0.25}
    
    operations = list(operation_mix.keys())
    weights = list(operation_mix.values())
    
    for i in range(num_mutations):
        file_size = os.path.getsize(file_path)
        
        if file_size == 0:
            print("File is empty, skipping mutation")
            continue
        
        # Randomly choose operation
        operation = random.choices(operations, weights=weights, k=1)[0]
        
        # Random pause between mutations
        pause = random.uniform(pause_range[0], pause_range[1])
        
        if operation == 'mutate':
            # Random offset and length
            offset = random.randint(0, file_size - 1)
            length = random.randint(1, min(512, file_size - offset))
            print(f"\n[{i+1}/{num_mutations}] Mutation operation")
            mutate_byte_range(file_path, offset, length, pause)
        
        elif operation == 'insert':
            # Random offset and size
            offset = random.randint(0, file_size)
            size = random.randint(1, 256)
            print(f"\n[{i+1}/{num_mutations}] Insert operation")
            insert_data(file_path, offset, size, pause)
        
        elif operation == 'remove':
            # Random offset and size
            if file_size > 1:
                offset = random.randint(0, file_size - 1)
                max_remove = file_size - offset
                size = random.randint(1, min(256, max_remove))
                print(f"\n[{i+1}/{num_mutations}] Remove operation")
                remove_data(file_path, offset, size, pause)


def main():
    parser = argparse.ArgumentParser(
        description="Randomly mutate files for testing diff and chunking algorithms"
    )
    parser.add_argument(
        "file",
        help="Path to the file to mutate"
    )
    parser.add_argument(
        "-n", "--mutations",
        type=int,
        default=10,
        help="Number of mutation operations (default: 10)"
    )
    parser.add_argument(
        "-m", "--min-pause",
        type=float,
        default=0.1,
        help="Minimum pause between mutations in seconds (default: 0.1)"
    )
    parser.add_argument(
        "-M", "--max-pause",
        type=float,
        default=0.5,
        help="Maximum pause between mutations in seconds (default: 0.5)"
    )
    parser.add_argument(
        "-s", "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility"
    )
    parser.add_argument(
        "--mutate-prob",
        type=float,
        default=0.5,
        help="Probability of mutation operation (default: 0.5)"
    )
    parser.add_argument(
        "--insert-prob",
        type=float,
        default=0.25,
        help="Probability of insert operation (default: 0.25)"
    )
    parser.add_argument(
        "--remove-prob",
        type=float,
        default=0.25,
        help="Probability of remove operation (default: 0.25)"
    )
    
    args = parser.parse_args()
    
    # Set random seed if provided
    if args.seed is not None:
        random.seed(args.seed)
    
    # Normalize probabilities
    total_prob = args.mutate_prob + args.insert_prob + args.remove_prob
    operation_mix = {
        'mutate': args.mutate_prob / total_prob,
        'insert': args.insert_prob / total_prob,
        'remove': args.remove_prob / total_prob,
    }
    
    try:
        print(f"Starting {args.mutations} mutations on: {args.file}")
        print(f"Pause range: {args.min_pause}s - {args.max_pause}s")
        print(f"Operation distribution: {operation_mix}\n")
        
        random_mutations(
            args.file,
            num_mutations=args.mutations,
            pause_range=(args.min_pause, args.max_pause),
            operation_mix=operation_mix
        )
        
        final_size = os.path.getsize(args.file)
        print(f"\n✓ Completed! Final file size: {final_size} bytes")
    
    except Exception as e:
        print(f"✗ Error: {e}", flush=True)
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
