from werkzeug.security import generate_password_hash

password = "admin123"  # غيّرها لكلمة المرور التي تريدها للأدمن
hash_value = generate_password_hash(password)
print(hash_value)