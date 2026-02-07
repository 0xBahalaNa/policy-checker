# Policy File Validator (policy_checker.py)

This script loads an AWS policy file and checks if it is overly permissive.

## Usage

1. `git clone` this repository. 
2. Update the `filename` variable inside the script as needed.
3. Run the script.

```
python policy_checker.py
```

## What It Does
- Loads a JSON policy file.
- Iterates over the `Statement` entries
- Checks for excessive permissions such as:
    - `Action` is `*`
    - `Resource` is `*`
- Prints a summary of the results.

## Requirements
- Python 3.x

## License
- MIT License