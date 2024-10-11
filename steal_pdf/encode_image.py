import base64

def image_to_base64(image_path):
    with open(image_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
    return encoded_string

# השתמש בפונקציה
image_path = "C:\my-CTF\communication\ctf_challenge.png"  # שנה זאת לנתיב האמיתי של התמונה שלך
base64_image = image_to_base64(image_path)

print("EMBEDDED_IMAGE_DATA = '''")
print(base64_image)
print("'''")

# אתה יכול גם לשמור את התוצאה לקובץ טקסט אם היא ארוכה מדי
with open("encoded_image.txt", "w") as text_file:
    text_file.write(f"EMBEDDED_IMAGE_DATA = '''\n{base64_image}\n'''")