from PyPDF2 import PdfReader

reader = PdfReader("test.pdf")
if reader.is_encrypted:
    # Try empty password (works if PDF allows partial access)
    reader.decrypt("")  
    
    text = ""
    for page in reader.pages:
        text += page.extract_text()
    print(text)