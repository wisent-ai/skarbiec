#!/usr/bin/env python3
"""
Validates that Swift client calls to /v1/operator/credential only use operations
the Rust broker supports. Fails on mismatch, reporting precise locations.

Extract broker-supported operations from src/net/operator.rs.
Extract client-called operations from BackendClient.swift.
Compare and fail if any client call is unsupported.
"""

import re
import sys
from pathlib import Path
from typing import Set, Dict, List, Tuple


def extract_broker_operations(operator_rs: Path) -> Set[str]:
    """Extract supported operations for /v1/operator/credential from operator.rs."""
    content = operator_rs.read_text()
    
    # Pattern to match: if !["status", "acquire", "rotate", "resume", ...].contains(&operation.as_str())
    pattern = r'if\s+!\s*\[(.*?)\]\s*\.contains\(&operation\.as_str\(\)\)'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        array_content = match.group(1)
        # Extract quoted strings: "status", "acquire", etc.
        ops = re.findall(r'"([^"]+)"', array_content)
        if ops:
            return set(ops)
    
    # Fallback: look for the error message "must be one of X, Y, Z"
    error_pattern = r'operator credential operation must be one of ([^"]*)'
    match = re.search(error_pattern, content)
    if match:
        ops_str = match.group(1).strip().rstrip('"').rstrip()
        # Parse comma-separated values
        ops = [op.strip() for op in ops_str.split(',')]
        if ops:
            return set(ops)
    
    raise ValueError("Could not find credential operation validation in operator.rs")


def extract_client_operations(backend_client: Path) -> Dict[str, List[Tuple[int, str, str]]]:
    """
    Extract all operations called on /v1/operator/credential from BackendClient.swift.
    
    Returns dict mapping operation name to list of (line_number, function_name, context).
    """
    content = backend_client.read_text()
    lines = content.split('\n')
    
    operations: Dict[str, List[Tuple[int, str, str]]] = {}
    
    # Track current function
    current_function = "unknown"
    for i, line in enumerate(lines, 1):
        # Track function definitions
        func_match = re.search(r'func\s+(\w+)\s*\(', line)
        if func_match:
            current_function = func_match.group(1)
        
        # Look for operation fields in /v1/operator/credential calls
        # Pattern: ["operation": "value", "item":
        operation_match = re.search(r'\["operation":\s*"([^"]+)"', line)
        if operation_match:
            operation = operation_match.group(1)
            context = line.strip()
            if operation not in operations:
                operations[operation] = []
            operations[operation].append((i, current_function, context))
    
    return operations


def validate_contract(broker_ops: Set[str], client_calls: Dict[str, List[Tuple[int, str, str]]]) -> bool:
    """
    Validate that all client operations are supported by broker.
    
    Returns True if valid, False if any operation is unsupported.
    Prints detailed diagnostics.
    """
    all_valid = True
    client_ops = set(client_calls.keys())
    unsupported = client_ops - broker_ops
    
    if unsupported:
        print("❌ BROKER-CLIENT CONTRACT VIOLATION", file=sys.stderr)
        print(f"\nUnsupported operations in client code:", file=sys.stderr)
        for op in sorted(unsupported):
            print(f"\n  Operation: {op}", file=sys.stderr)
            for line_no, func, context in client_calls[op]:
                print(f"    - {func}() at line {line_no}", file=sys.stderr)
                print(f"      {context}", file=sys.stderr)
        
        print(f"\nBroker supports: {sorted(broker_ops)}", file=sys.stderr)
        print(f"Client calls:   {sorted(client_ops)}", file=sys.stderr)
        all_valid = False
    else:
        print("✓ All client operations are supported by broker")
        print(f"  Supported: {sorted(broker_ops)}")
        print(f"  Used: {sorted(client_ops)}")
    
    return all_valid


def main():
    if len(sys.argv) < 3:
        print("Usage: check-broker-client-contract.py <operator.rs> <BackendClient.swift>")
        sys.exit(1)
    
    operator_rs = Path(sys.argv[1])
    backend_client = Path(sys.argv[2])
    
    if not operator_rs.exists():
        print(f"Error: {operator_rs} not found", file=sys.stderr)
        sys.exit(1)
    
    if not backend_client.exists():
        print(f"Error: {backend_client} not found", file=sys.stderr)
        sys.exit(1)
    
    try:
        broker_ops = extract_broker_operations(operator_rs)
        client_calls = extract_client_operations(backend_client)
        
        if validate_contract(broker_ops, client_calls):
            sys.exit(0)
        else:
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
