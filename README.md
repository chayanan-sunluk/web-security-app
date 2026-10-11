# Board — Flask Web App

## รันในเครื่อง
```
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export ADMIN_USERNAME=admin ADMIN_PASSWORD='1234'   # Windows: set ...
python app.py        # เปิด http://127.0.0.1:5000
```
แอดมินคนแรกถูกสร้างจาก env ข้างบน (สมัครเองได้เป็น `user` เท่านั้น)

## เอาขึ้นโฮส (ส่งลิงก์ใน Classroom)
**Render.com (ฟรี):** push โค้ดขึ้น GitHub → New > Web Service → เลือก repo
- Build: `pip install -r requirements.txt`  Start: `gunicorn app:app`
- Environment: `FLASK_ENV=production`, `SECRET_KEY=<สุ่มยาวๆ>`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`
- ดิสก์ฟรีของ Render ถูกล้างเมื่อ redeploy → ถ้าต้องการข้อมูลถาวร สร้าง Postgres ฟรี (Render/Neon/Supabase) แล้วใส่ `DATABASE_URL`
**PythonAnywhere (ง่ายสุดสำหรับ SQLite):** อัปโหลดโค้ด → Web > Flask → ตั้ง env ใน WSGI file

## ตาราง "การป้องกันการโจมตี" (ไว้ตอบตอนตรวจ)
| การโจมตี | วิธีป้องกัน | อยู่ที่ |
|---|---|---|
| รหัสผ่านรั่ว | แฮช scrypt + salt (werkzeug) ไม่เก็บ plaintext | `generate_password_hash` |
| SQL Injection | ใช้ ORM (SQLAlchemy) = parameterized query | `User.query.filter_by` |
| XSS | Jinja2 autoescape + CSP `script-src 'none'` + cookie HttpOnly | `templates/`, `headers()` |
| CSRF | CSRF token ทุกฟอร์ม POST + SameSite=Lax | `CSRFProtect` |
| Brute force | Flask-Limiter: login 5/นาที, สมัคร 10/ชม. | `@limiter.limit` |
| IDOR / แก้ข้อมูลคนอื่น | เช็ก `owner_id == current_user.id` ฝั่งเซิร์ฟเวอร์ → 403 | `owned_post_or_403` |
| ยกระดับสิทธิ์ | `@admin_required`; สมัครได้เป็น user เท่านั้น; แอดมินเปลี่ยน/ลบตัวเองไม่ได้ | `admin_required` |
| User enumeration | ข้อความ login ผิดเหมือนกัน + เช็กแฮชเสมอ (dummy hash) | `login()` |
| Session hijack | cookie HttpOnly/Secure/SameSite, logout ด้วย POST | `app.config` |
| Clickjacking / MIME sniff | X-Frame-Options, CSP frame-ancestors, nosniff | `headers()` |
| Input ใหญ่/ผิดรูป | validate ความยาว/regex ฝั่งเซิร์ฟเวอร์ + MAX_CONTENT_LENGTH | `Form` classes |
| ลบด้วย GET | การลบ/แก้ไขเป็น POST + CSRF ทั้งหมด | routes |

## แนวตอบคำถาม (5 คะแนน)
- **ทำไมต้องแฮช ไม่เข้ารหัส?** แฮชย้อนกลับไม่ได้ แม้ DB รั่วก็ถอดรหัสผ่านตรง ๆ ไม่ได้; salt ทำให้รหัสเหมือนกันได้แฮชต่างกัน; scrypt/pbkdf2 ช้าโดยตั้งใจเพื่อกัน brute force
- **ป้องกัน SQLi ยังไง?** ORM ส่งค่าเป็น parameter แยกจากคำสั่ง SQL ไม่ต่อ string
- **CSRF คืออะไร?** เว็บอื่นหลอกให้เบราว์เซอร์ที่ล็อกอินอยู่ส่งคำสั่งมาที่เรา; กันด้วย token ลับต่อ session ที่ผู้โจมตีเดาไม่ได้
- **XSS คืออะไร?** ใส่สคริปต์ผ่านฟอร์ม; กันด้วย escape ตอนแสดงผล + CSP (ลองโพสต์ `<script>alert(1)</script>` จะแสดงเป็นข้อความ)
- **Authentication vs Authorization?** ยืนยันตัวตน (login) vs ตรวจสิทธิ์ (role/เจ้าของ)
- **ข้อจำกัดที่รู้:** rate limit เก็บในหน่วยความจำ (production จริงควรใช้ Redis), ยังไม่มี email verification / 2FA
