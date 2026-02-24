#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Show help
show_help() {
    echo "Usage: $0 <mode> <file> <password>"
    echo ""
    echo "Modes:"
    echo "  encrypt, enc, e    Encrypt file"
    echo "  decrypt, dec, d    Decrypt .bcvx file"
    echo ""
    echo "Examples:"
    echo "  $0 encrypt file.txt 'MyPass123'"
    echo "  $0 dec file_enc.bcvx 'MyPass123'"
    echo "  $0 e document.txt 'P@ssw0rd'"
    exit 0
}

# Chec dependecies
if [ ! -f "enc.py" ] || [ ! -f "dec.py" ]; then
    echo -e "${RED}Error: enc.py or dec.py not found${NC}"
    exit 1
fi

# Parse args
MODE=$1
FILE=$2
PASS=$3

if [ -z "$MODE" ] || [ -z "$FILE" ] || [ -z "$PASS" ]; then
    show_help
fi

# Process basez on md
case $MODE in
    encrypt|enc|e)
        echo -e "${YELLOW}Encrypting: $FILE${NC}"
        python3 enc.py enc "$FILE" --pass "$PASS"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Encryption successful${NC}"
        else
            echo -e "${RED}✗ Encryption failed${NC}"
            exit 1
        fi
        ;;
        
    decrypt|dec|d)
        echo -e "${YELLOW}Decrypting: $FILE${NC}"
        python3 dec.py -d "$FILE" --pass "$PASS"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Decryption successful${NC}"
        else
            echo -e "${RED}✗ Decryption failed${NC}"
            exit 1
        fi
        ;;
        
    help|-h|--help)
        show_help
        ;;
        
    *)
        echo -e "${RED}Error: Unknown mode '$MODE'${NC}"
        show_help
        ;;
esac
