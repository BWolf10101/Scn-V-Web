Ini merupakan tools sederhan yang di buat hanya untuk ujicoba tahap pengembangan pertama saya dalam membuat system scanning pada web, kerja dari tools ini cukup sederhana,untuk medeteksi kerentanan seperti atau pada:
XSS 
SQLi 
LFI
RCE
SSRF
tools ini masih tahap pengembangan,saya perlu belajar lebih dalam terlebih dahulu untuk pentesting atau dalam bidang sebagai black hat untuk memahmi struktur kejahatan cyber lebih dalam,mungkin akan ada sedikit masalah pada tools di saat di gunakan tapi tools ini tetap dapat bekerja untuk uji coba pentesting

rangkuman fitur utama:
   - Multi-threading:
    
       Meningkatkan kecepatan scan dengan menggunakan multiple threads.
       
       Terutama untuk brute force directories dan parallel testing.

   - Deteksi Teknologi:

        Mengidentifikasi CMS (WordPress, Joomla, Drupal)

        Mendeteksi framework (Laravel, React, Vue, Angular)

        Menganalisis header server dan X-Powered-By

   - WAF Detection:

        Mendeteksi Cloudflare, Sucuri, Imperva, dan WAF lainnya

        Memeriksa tanda-tanda WAF berdasarkan header dan response time

   - Rate Limiting Check:

        Memantau response time untuk mendeteksi pembatasan request

        Penyesuaian otomatis berdasarkan kondisi server

   - Enhanced Payloads:

        Payload khusus untuk XSS, SQLi, LFI, RCE, dan SSRF

        Support file payload eksternal atau menggunakan default

   - Security Headers Check:

        Memeriksa header keamanan seperti CSP, HSTS, X-Frame-Options

        Memberi rekomendasi untuk perbaikan

   - Reporting System:

        Laporan dalam format TXT dan HTML

        Klasifikasi kerentanan berdasarkan tingkat keparahan

        Highlight untuk temuan penting

   - Advanced Crawling:

        Mendeteksi semua link termasuk script, img, dan iframe

        Support depth-limited crawling untuk menghindari infinite loop

   - Error Handling:

        Penanganan error yang lebih baik untuk berbagai kondisi

        Logging yang informatif untuk troubleshooting

   - Parameterized Testing:

        Testing semua parameter URL untuk berbagai kerentanan

        Support GET dan POST parameters

     install depedensi ini terlebih dahulu:
     pip install requests fake-useragent colorama dnspython urllib3 cryptography
     pip install requests beautifulsoup4 fake-useragent colorama urllib3
     
cara penggunaan:

"python scanwebvuln.py (target domain) -t 20 -o scan_results"

opsi parameter:

target       : URL target yang akan di-scan
-w/--wordlist: Path ke custom wordlist (opsional)
-t/--threads : Jumlah threads (default: 10)
-o/--output  : Direktori output untuk laporan (default: reports)
-to/--timeout: Timeout request dalam detik (default: 10)


