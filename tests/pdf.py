import sys
from PyPDF2 import PdfReader

def extract_text_from_pdf(pdf_path = "test.pdf", output_txt=None):
    """
    Attempts to extract text from a password-protected PDF that allows copying.
    Works on PDFs with weak encryption or partial decryption.
    """
    reader = PdfReader(pdf_path)
    
    if reader.is_encrypted:
        # Try empty password (works if PDF allows partial access)
        if reader.decrypt(""):
            print("[+] PDF decrypted with empty password!")
        else:
            print("[-] Failed to decrypt. PDF may have strong encryption.")
            return False
    
    # Extract text
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""  # Handle None returns
    
    if not text.strip():
        print("[-] No text extracted. PDF may be image-based or fully encrypted.")
        return False
    
    # Save to file (if output path given)
    if output_txt:
        with open(output_txt, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[+] Text saved to: {output_txt}")
    else:
        print("\n=== Extracted Text ===")
        print(text[:1000] + "..." if len(text) > 1000 else text)  # Preview
    
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pdf_text_extractor.py <PDF_FILE> [OUTPUT_TXT]")
        sys.exit(1)
    
    pdf_path = sys.argv[1]
    output_txt = sys.argv[2] if len(sys.argv) > 2 else None
    
    extract_text_from_pdf(pdf_path, output_txt)