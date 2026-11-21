# TCTC Guardian Z797

**First public release: `v1.0.0`** · Windows-focused investigation and response for the specifically analysed TCTC / Z797 ClickFix chain.

[English](#english)

---

### 1. ما الذي قمنا بتحليله؟

التحليل ركّز على سلسلة إصابة متعددة المراحل تبدأ بحيلة **ClickFix**: صفحة مزيفة تقلّد Cloudflare وتوهم المستخدم بأنه ينفّذ خطوة تحقق بشرية. بدلًا من CAPTCHA طبيعي، تطلب الصفحة من المستخدم فتح نافذة Run أو Command Prompt ولصق أمر وتشغيله. دي نقطة الدخول الأساسية؛ خدمة CAPTCHA شرعية لا تحتاج من المستخدم تشغيل أوامر PowerShell.

السلسلة التي أعدنا بناءها مرتبطة بالملفات `crandle.txt` و`Z797.ps1` وملف الحمولة المشفّر `tctc.bba`. أقرب بحث علني مطابق يصف سلسلة التوصيل بأنها مرتبطة بـLegionLoader، لكن تسمية العائلة ليست محسومة بالكامل: سجل ThreatFox رقم 2031306 يضع تصنيف Stealc، بينما تقرير Plume الأقرب لهذه السلسلة يصف LegionLoader. لذلك نستخدم اسم **سلسلة TCTC / Z797** للدلالة على العينة المحددة، ونوضح اختلاف التصنيفات بدل الجزم باسم عائلة واحد.

التحليل تم Offline باستخدام الملفات التي تم توفيرها، وفحص PE، والتحليل الساكن للتعليمات، وإعادة بناء وفك تشفير المراحل المستخرجة، ومراجعة بيانات اتصال تم التقاطها سابقًا. **لم نشغّل أي عينة أو أداة مساعدة خبيثة، ولم نتصل بأي سيرفر C2 أو سيرفر توزيع مشتبه به.**

### 1.1 أمر التشغيل الأولي الذي ينسخه المستخدم (تحليل منزوع قابلية التنفيذ)

الأمر الذي أرسلته لنا يمثل **نقطة التنفيذ الأولى من جهة المستخدم** في سلسلة الإصابة. أضفت تحليله هنا بصيغة وصفية مفككة، وليس كسطر Shell جاهز للنسخ والتشغيل؛ لذلك لن نعيد نشر سلسلة التحميل والتنفيذ بصيغة قابلة للتشغيل.

| الخطوة المرصودة | ماذا تفعل؟ | لماذا تهم؟ |
|---|---|---|
| تعيين `__VSCMD_WIN_64BIT=true` | تنشئ أو تستبدل متغير بيئة داخل نافذة الأوامر الحالية. | مجرد علامة داخل البيئة؛ ولا تثبت وحدها وجود Visual Studio أو استخدام أدواته. |
| الانتقال إلى `%TEMP%` | تجعل مجلد الملفات المؤقتة هو مجلد العمل الحالي. | تصبح المسارات النسبية التالية مرتبطة بمكان مؤقت قابل للكتابة عادةً. |
| جلب `crandle.txt` من مسار `/454` | يستخدم الأمر المرسل `curl.exe -sLo` لحفظ الاستجابة باسم `crandle.txt`. | الخيار `-s` يخفي مخرجات التقدم المعتادة، و`-L` يتبع التحويلات، و`-o` يحفظ الاستجابة في ملف؛ ولا يظهر في السطر فحص توقيع أو بصمة للمحتوى. |
| جلب `Z797.ps1` من مسار `/455` | يحفظ استجابة ثانية باسم `Z797.ps1` داخل مجلد Temp. | يتم تجهيز الملف بجوار `crandle.txt`؛ لكن النص المرسل وحده لا يثبت نجاح تنزيله أو تشغيله. |
| تفسير أسطر `crandle.txt` كأوامر | بنية `for /f` الأخيرة تقرأ الملف سطرًا بسطر، ثم تمرر كل سطر إلى مفسّر الأوامر للتنفيذ. | دي أهم نقطة تسليم: النص الذي تم تنزيله لا يُعامل كمستند عادي، بل كتعليمات قابلة للتنفيذ. والخطوة التالية الفعلية تعتمد على محتوى `crandle.txt`. |

**تسلسل منزوع قابلية التنفيذ:** تعيين متغير البيئة ← الانتقال إلى `%TEMP%` ← حفظ الاستجابتين باسم `crandle.txt` و`Z797.ps1` من مساري `/454` و`/455` ← تمرير كل سطر من `crandle.txt` إلى مفسّر الأوامر. الوصف يحافظ على السلوك المهم للتحليل دون نشر أمر تحميل وتشغيل جاهز.

**اختلاف في عنوان التوصيل:** النص الذي أرسلته يحتوي على قيمة المضيف الرقمية `1566454788`. إذا فُسرت كعنوان IPv4 عشري 32-bit بترتيب الشبكة المعتاد، فإنها تقابل `93.94.52.4`. بينما يسجل التحليل المحلي السابق العنوان `93.94.52.29` لنشاط التوصيل الأول. العنوانان مختلفان؛ لذلك نحتفظ بـ`93.94.52.4` كـ**عنوان مرشح غير مؤكد مستنتج من نص الأمر الجديد**، ولا ندمجه مع مؤشر `.29` السابق قبل وجود دليل مؤيد من DNS أو HTTP أو سجل المتصفح أو PCAP. نص الأمر وحده لا يثبت نجاح الاتصال أو التنزيل.

### 2. تسلسل الإصابة الذي أعدنا بناءه

1. صفحة Cloudflare مزيفة تعرض تعليمات ClickFix وتطلب من المستخدم لصق أمر وتشغيله من Run أو Command Prompt.
2. الأمر الأول يجلب `crandle.txt` و`Z797.ps1` من بنية التوزيع التي ظهرت في التحليل؛ عنوان التوزيع المرصود هو `93[.]94[.]52[.]29`.
3. سكربت PowerShell مشوّه يعيد تكوين سكربت أصغر داخل الذاكرة، ويعرض نافذة تحقق مزيفة باسم `CloudTrust Auth`.
4. المرحلة التالية تجلب `tctc.bba` المشفّر، ثم تمر السلسلة بمراحل فك تشفير وتنفيذ داخل الذاكرة. المواد المستخرجة تشير إلى طبقات XTEA وAES.
5. بعد ذلك يعمل Controller داخلي يعتمد على المهام القادمة من البنية البعيدة، ويستطيع استقبال أوامر وملفات إضافية وإرسال حالة تنفيذ المهام.

تتضمن السلسلة فحوصًا للبيئة مثل معلومات أجهزة العرض ومعلومات عنوان IP العام وASN. ظهور `ipinfo[.]io` وحده ليس دليل إصابة؛ تم استخدامه كسياق لفحوص بيئة التشغيل ومكافحة التحليل.

### 3. قدرات الـController التي وجدناها

الـController الداخلي ليس مجرد Downloader بسيط؛ هو مكوّن Windows قائم على المهام. التحليل الساكن كشف مسارات كود تدعم:

- **الاتصال واستقبال المهام:** النطاق المستخرج من إعدادات الـController هو `benderoflight[.]com`. المسار `/nfront.php` للتسجيل واستقبال المهام، و`/nback.php` لإرسال نتائجها. الرسائل التي تمت مراجعتها تستخدم Base64 framing مع تحويل RC4 لمحتوى الرسالة.
- **التعامل مع الملفات والحمولات:** توجد معالجات لمهام ملفات PE وShellcode وPowerShell/Script وMSI، بالإضافة إلى التنزيل والكتابة وفك بعض الأرشيفات. النتيجة تعتمد على المهمة والحمولة التي يرسلها المشغّل.
- **مسارات متعددة للتعامل مع العمليات:** مسارات منفصلة تستهدف RuntimeBroker، وتنشئ عمليات فرعية معلّقة، وتستخدم تنفيذًا داخل ذاكرة عملية أخرى، ومسارات إنشاء Image-backed process، ومسار APC مرتبطًا بـExplorer. هذه أساليب مختلفة ولا يصح اختزالها كلها في وصف واحد مثل Process Hollowing.
- **محاولة العبث بـAMSI:** يوجد مسار يجهّز stubs قصيرة تستهدف `AmsiScanString` و`AmsiScanBuffer`. هذا يثبت وجود محاولة/قدرة في الكود، لكنه لا يثبت نجاح تعديل الذاكرة أو تجاوز AMSI فعليًا على جهاز مصاب.
- **الاستمرارية:** يحتوي الـController على كود مشروط لكتابة قيم Run / RunOnce. وجود الكود لا يثبت أن المهمة وصلت أو أن الاستمرارية تم تثبيتها على الجهاز الذي نحلله.
- **مفاتيح Chrome:** النسخة التي راجعناها تقرأ مواد مرتبطة بمفتاح Chrome من `Local State`، وتحتوي Helper يستخدم واجهة Chrome App-Bound decryption. صلاحيات Named Pipe الخاصة بالـHelper متساهلة. دي قدرة مرتبطة بالوصول لبيانات الاعتماد، لكن لا يوجد دليل كافٍ أن المفتاح استُخرج بنجاح ثم تم رفعه للسيرفر.
- **Dynamic Modules:** يوجد نظام داخلي لتحميل/توزيع وحدات وطرق تنفيذ إضافية. أجسام بعض الطرق الديناميكية لم تكن متاحة ضمن الملفات التي تمت مراجعتها، لذلك لا يمكن الجزم بوظيفتها النهائية.

وجود المسارات دي في الكود لا يعني أن المشغّل استخدم كل واحدة منها أو أنها نجحت على جهاز بعينه. طبيعة الـController تسمح بتغيير السلوك حسب المهام والوحدات التي تصل لاحقًا.

### 4. ما ثبت وما لم يثبت

| الموضوع | خلاصة الأدلة |
|---|---|
| صفحة ClickFix والتحقق المزيف | موجودة في سلسلة الإصابة التي أُعيد بناؤها |
| `crandle.txt` و`Z797.ps1` و`tctc.bba` | ملفات ومراحل تم استردادها وتحليلها |
| هوية الـController | تطابق قوي ببصمة SHA-256 مع Controller حجمه 494,080 بايت في ThreatFox IOC 2031306 |
| مسارات `/nfront.php` و`/nback.php` | مستخرجة من إعدادات ثابتة وبيانات معاملة قديمة تمت مراجعتها Offline |
| مسارات تنفيذ العمليات والذاكرة | موجودة في الكود الذي تم تحليله؛ نجاح تنفيذها على ضحية غير مثبت بمجرد وجود الكود |
| العبث بـAMSI | مسار محاولة موجود؛ نجاح التجاوز غير مثبت |
| Run / RunOnce | قدرة مشروطة موجودة؛ التثبيت الفعلي غير مثبت |
| Chrome key helper | قدرة استرجاع موجودة؛ استخراج المفتاح ورفعه غير مثبتين |
| خمس أسماء ملفات في استجابة مهام | تمت مراجعة `42.bin`؛ الأربعة الأخرى لم تكن متاحة في مجموعة الأدلة |
| سرقة كلمات مرور أو Cookies أو رفعها | غير مثبتة في بيانات المعاملة المتاحة |
| تشفير جماعي/فدية أو Keylogging تقليدي أو تصوير كاميرا/ميكروفون | لم يثبت وجودها في الـController الأساسي المسترد |

عدم إثبات السلوك لا يعني استحالة حدوثه في وحدة ديناميكية أو حمولة لاحقة. بعض أجسام الوحدات والملفات التي طلبها السيرفر لم تكن ضمن مجموعة الأدلة. كما أن أول تحويل للملف الخام `tctc.bba` لم يكن قابلًا لإعادة الإنتاج بالكامل من المواد المتاحة. تغطية الـDisassembly المحفوظة واسعة، لكنها لا تعني مراجعة بشرية دلالية لكل دالة.

### 5. بصمات الملفات المستردة

البصمات التالية موجودة للمساعدة في التعرف الدفاعي والمقارنة فقط. **المستودع لا يحتوي على عينات الفيروس أو ملفات PE التنفيذية المستخرجة أو ملفات PCAP التي تحتوي الحمولة.**

| الملف | الحجم | SHA-256 |
|---|---:|---|
| Outer PE الأصلي | 8,147,456 بايت | `077c93f044b590a017771ced5067e8adde18d629598ea545496904dafcfd8e22` |
| ملف `tctc.bba` الخام | 8,178,288 بايت | `c34719ff34d037eedc4338655d844734a7451c00250a56c8cba8f807f92bcafb` |
| Stage-2 shellcode المسترد | 8,328,272 بايت | `ce9263eec902131910d6ff69b33f2d61f09707dadb7818c11de46d97fa441169` |
| Stage-3 PE المعاد بناؤه | 8,324,608 بايت | `30a16519c20df8f6d7fd8e127c5e2ba688b074eb723c60ed88e36b1da3cc1b12` |
| الـController الداخلي | 494,080 بايت | `a10e4fbff548ea2839db1cac5faaa3316b950cc9f8a2cf82658b1a9ad7eb9089` |
| نسخة النقل المشفرة `42.bin` | 736,768 بايت | `4dd38c86f35b68702d47d3bb90c8dc694e9b85d179b0825fb1aea05d3e60a335` |
| نسخة PE المفكوكة من `42.bin` | 736,768 بايت | `4a5e0ed88529761af8e86afcf2b969217a7345abe2c467523d036bb5126ca644` |

### 6. مؤشرات الشبكة (مخفّضة الصياغة)

دي مؤشرات تاريخية ظهرت في السلسلة التي تم تحليلها؛ ممكن تكون قديمة أو معاد استخدامها أو غير مكتملة. لا تحظر IP أو Domain لمجرد ظهوره هنا؛ لازم تربطه بالعملية والتوقيت والمسار وأدلة أخرى.

| المؤشر | دوره وملاحظته |
|---|---|
| `93[.]94[.]52[.]29` | سيرفر التوصيل الأول المرتبط بـ`crandle.txt` و`Z797.ps1` |
| `1566454788` → `93[.]94[.]52[.]4` (مرشح غير مؤكد) | تفسير القيمة الرقمية في أمر التشغيل الأولي كعنوان IPv4 عشري؛ لا يوجد تأكيد مستقل، وهي مختلفة عن `93[.]94[.]52[.]29` |
| `benderoflight[.]com` | نطاق الـController الداخلي المستخرج |
| `hxxps://benderoflight[.]com/nfront.php` | تسجيل الجهاز واستقبال المهام |
| `hxxps://benderoflight[.]com/nback.php` | إرسال حالة/نتيجة المهام |
| `survivomatic[.]com` | نطاق استضافة مرتبط بمهمة `42.bin` في الاستجابة التي تمت مراجعتها |
| `ruthaiv[.]com` | نطاق استضافة لملفات مهام أخرى في الاستجابة نفسها |
| `ipinfo[.]io` | فحص IP/ASN للبيئة؛ مؤشر سياقي وليس خبيثًا بمفرده |
| `109[.]238[.]86[.]137` | وجهة اتصال TLS في المعاملة المحلية التي تمت مراجعتها؛ ظهر العنوان أيضًا في سياقات أخرى، لذلك التطابق بالـIP وحده لا يثبت هذه الإصابة |

الاستجابة التي تمت مراجعتها تضمنت أسماء خمس مهام: `42.bin` و`eeGai2ahyae.bin` و`awpg2gawa2.fjk` و`1488.bin` و`just_test.bin`. الملف الوحيد المتاح ضمن مجموعة الأدلة كان `42.bin`؛ لا نستنتج وظيفة الملفات الأربعة الأخرى من أسمائها.

### 7. أداة Guardian بتفحص إيه؟

Guardian مصممة لسلسلة TCTC / Z797 المحددة، وليست Antivirus عامة ولا تحاول كشف كل حملات ClickFix أو LegionLoader.

| المجال | نطاق الفحص |
|---|---|
| العمليات | تعداد العمليات والمسارات وربط هوية الملف التنفيذي ببصمات العينة أو تسلسل العمليات المرتبط |
| الذاكرة الحية | فحص Read-only لقائمة محددة: `RuntimeBroker.exe` و`explorer.exe` و`chrome.exe`، و`csc.exe` فقط إذا كان يعمل من مسار التجهيز الذي ظهر في التحليل |
| ملفات التجهيز | مسارا `%TEMP%\Local` و`%WINDIR%\Temp\Local` فقط، مع بصمات الملفات والأحجام والأسماء وعلامات المحتوى المستردة |
| الاستمرارية | Run / RunOnce وStartup والخدمات والمهام المجدولة المرتبطة بأمر Z797 محدد، وبعض أدلة WMI التاريخية |
| الشبكة | DNS Cache وHosts والاتصالات الحالية؛ لا تتحول المطابقة إلى Finding قوي من غير ربطها بهوية العملية والسياق الصحيح |
| السجلات | Sysmon وWindows Security وPowerShell 4103/4104 وTask Scheduler وWMI، عند وجود مؤشر Z797 أو ربط صحيح بالعملية المصدر |
| المراقبة المستمرة | المراقبة المختارة والأحداث الجديدة طالما البرنامج مفتوح أو في Tray |

خارج النطاق: بيانات المتصفح الشخصية وسجل التصفح، ملفات Temp العشوائية، تنبيهات Windows Defender العامة، مؤشرات حملات أخرى، وأي شذوذ عام غير مرتبط بأدلة Z797.

### 8. فاحص الذاكرة: شغل حقيقي وحدود واضحة

فاحص الذاكرة مسار Windows API حقيقي للقراءة فقط، وليس مجرد مؤشر في الواجهة. يفتح العمليات المؤهلة بصلاحيات الاستعلام والقراءة، ويستخدم `VirtualQueryEx` لتعداد بيانات مناطق الذاكرة، و`ReadProcessMemory` لقراءات مستهدفة لمناطق محددة وفحص ترويسات PE، و`QueryWorkingSetEx` لمراجعة صفحات الصور التنفيذية المقيمة، وToolhelp لتعداد Threads وModules، و`NtQueryInformationThread` للاستعلام عن بداية Threads، ويفحص صادرات AMSI المعروفة عندما تكون `amsi.dll` موجودة وقابلة للقراءة.

التقرير يعرض عدادات استدعاءات API والمناطق والبايتات المقروءة ونتائج كل PID وفجوات الوصول. لكنه **لا يفرّغ ذاكرة كل العمليات ولا يقرأ كل بايت في الذاكرة**. العمليات المحمية وصلاحيات الوصول واختلاف المعمارية والصفحات غير المتاحة قد تقلل التغطية. منطقة تنفيذية خاصة أو صفحة Copy-on-Write أو اسم عملية أو ملاحظة AMSI منفردة لا تثبت الإصابة. Guardian لا يكتب في ذاكرة عملية أخرى، ولا يعدّل صفحاتها، ولا يحقن Threads أو يضع APCs.

### 9. إجراءات الاستجابة وحدود التنظيف

Guardian لا يعرض إجراء تنظيف إلا إذا كان يمكن إعادة التحقق من هدف موجود حاليًا. وفق الأدلة وموافقة المستخدم، يمكنه:

- عزل ملف عينة بعد إعادة التحقق من المسار والحجم وSHA-256 ونوع الملف.
- إيقاف عملية حية فقط عندما تطابق ملفًا مستردًا بدقة وتتم إعادة التحقق من هوية العملية.
- حفظ نسخة احتياطية ثم إزالة قيمة Run / RunOnce المطابقة وحدها.
- حفظ تفاصيل مهمة مجدولة أو خدمة وتعطيل العنصر الذي لا يزال أمره مرتبطًا بالعينة بدقة.
- حفظ نسخة Hosts وإزالة التحويل المطابق فقط.
- اقتراح قاعدة Firewall محددة عند ربط عنوان مؤكد بعملية تطابق الحمولة، وبعد موافقة المستخدم.

الأحداث التاريخية وDNS Cache وRunMRU والشذوذ العام في الذاكرة وأسماء العمليات وعناوين IP المنفردة هي أدلة للمراجعة وليست أهداف تنظيف. البرنامج لا يمسح بيانات المتصفح، ولا يفرّغ DNS بالكامل، ولا يحذف ملفات Temp غير المرتبطة، ولا يمسح سجلات Windows. الاحتواء التلقائي محصور في SHA-256 والحجم والمسار وهوية العملية المطابقة بدقة.

### 10. Sysmon والاختبار الآمن

يتم تنزيل Sysmon وقت التشغيل من مصدر Microsoft الرسمي والتحقق منه قبل الاستخدام. الإعداد الافتراضي هو **Event 29 detect-only**؛ Guardian لا يفعّل Event 27 ولا يحظر إنشاء ملفات PE.

لاختبار البرنامج بدون تشغيل الفيروس:

1. شغّل `Run-Safe-Z797-Lab.bat`.
2. افتح Guardian واعمل Scan.
3. راجع الأدلة التي تحمل `[LAB]` ودرجة `Info`.
4. جرّب العزل اليدوي على ملف Canary النصي فقط.
5. بعد الانتهاء شغّل `Cleanup-Safe-Z797-Lab.bat`.

المحاكي ينشئ ملف TXT خاملًا ويشغّل أمر `cmd.exe echo` بسيطًا لتوليد أحداث Process/File عادية عند توافر Sysmon. لا ينفذ حقن عمليات أو تعديل AMSI أو Persistence أو وصولًا لبيانات الاعتماد أو اتصالًا بالشبكة أو كتابة في ذاكرة عملية أخرى. التفاصيل والحدود في [`docs/SAFE-LAB-AR.md`](docs/SAFE-LAB-AR.md).

### 11. التشغيل والتحقق

المتطلبات: Windows 11 أو Windows Server 2019+ مدعوم، Python 3.11+، وموافقة Administrator عند الحاجة لتثبيت الحساس أو تنفيذ إصلاحات نظام.

```powershell
python -m pip install -r requirements.txt
python src/main.py
```

أو شغّل `Run-TCTC-Guardian.bat`. أول تثبيت مستقل لـSysmon يستخدم نافذة UAC المعتادة ويطلب قبول ترخيص Microsoft Sysinternals عند الحاجة.

اختبارات الحزمة المسجلة: 252 اختبار Python، و`compileall`، و`--self-check`، واختبار دورة Safe Lab، وفحص XML وسياسة Sysmon، وسلامة ZIP. الاختبارات تم تشغيلها في بيئة Linux باستخدام Fixtures وMocks، ولا تثبت نجاح WinTrust أو UAC أو تثبيت Driver الخاص بـSysmon أو Event Log الحي أو قراءة ذاكرة عمليات Windows أو تنفيذ إجراءات التنظيف على Windows أو عرض Qt وDPI. يجب استكمال [`docs/WINDOWS-VALIDATION.md`](docs/WINDOWS-VALIDATION.md) على جهاز Windows تجريبي معزول قبل الاعتماد على الاستجابة الحية أو توزيع نسخة تنفيذية.

حدود إضافية:

- لا يوجد Full Disk Scan أو Kernel Driver أو API Hook شامل أو ضمان منع التنفيذ قبل حدوثه.
- المراقبة المستمرة تتوقف عند إغلاق التطبيق؛ Guardian ليس Windows Service.
- السجلات التاريخية تعتمد على تفعيل الـProvider وسياسة التدقيق ومدة الاحتفاظ والصلاحيات قبل وقوع الحادث.
- الوحدات الديناميكية والمهام المستقبلية خارج ملف المؤشرات المسترد لا يمكن استنتاجها من التحليل الساكن وحده.
- نتيجة فحص نظيفة لا تثبت إزالة العدوى بالكامل. لو ثبت تنفيذ العينة مع وجود عبث غير محسوم بالعمليات أو الاستمرارية، تعامل مع الأمر كحادث أمني واحفظ الأدلة وفكّر في إعادة بناء Windows من مصدر موثوق.

### 12. إشعارات تراخيص المكونات الخارجية وواجهات نظام التشغيل

تم تطوير مشروع **TCTC Guardian Z797** باستخدام المكونات الخارجية وواجهات نظام التشغيل التالية:

- **Python** — يخضع لترخيص PSF. راجع [تفاصيل الترخيص](https://docs.python.org/3/license.html).
- **PySide6 / Qt for Python** — تختلف شروط الترخيص حسب الوحدات المستخدمة وطريقة توزيع البرنامج. يُرجى مراجعة [ملاحظات الترخيص الرسمية](https://doc.qt.io/qtforpython-6/licenses.html) قبل توزيع نسخة تنفيذية من البرنامج.
- **watchdog** — مكتبة Python لإشعارات ومراقبة تغييرات نظام الملفات. يُرجى مراجعة بيانات الترخيص المرفقة بها عند إعداد أي نسخة للتوزيع.
- **Nuitka** — أداة اختيارية لبناء وتجميع التطبيق: [الموقع الرسمي](https://nuitka.net/).
- **Microsoft Sysmon** — يتم تنزيله أثناء تشغيل البرنامج مباشرةً من نقطة التوزيع الرسمية لشركة Microsoft، ولا يتم تضمينه أو إعادة توزيعه ضمن حزمة السورس هذه. راجع [شروط ترخيص Sysinternals](https://learn.microsoft.com/en-us/sysinternals/license-terms) و[الأسئلة الشائعة حول الترخيص](https://learn.microsoft.com/en-us/sysinternals/license-faq).
- **واجهات Windows APIs / Event Log / Task Scheduler / Registry / Firewall** — واجهات مدمجة في نظام التشغيل Windows، ولا يتم تضمين أي حزمة SDK خارجية تابعة لمورّد آخر لاستخدام هذه الواجهات.

للاطلاع على الإشعارات التفصيلية والمحافظة عليها، راجع [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

### 13. حقوق المشروع وحالة الترخيص
**حقوق النشر © 2026 Jo0X01. جميع الحقوق محفوظة.**
[`LICENSE.md`](LICENSE.md)
المستودع الرسمي للمشروع: [https://github.com/Jo0X01/TCTC-Guardian-Z797](SOURCE).


**الكود الأصلي لمشروع TCTC Guardian Z797 غير مطروح بموجب رخصة GNU GPL أو أي ترخيص آخر مفتوح المصدر. جميع الحقوق محفوظة (All rights reserved).** إتاحة المستودع للعامة لا تمنح إذنًا بنسخ كود المشروع الأصلي أو تعديله أو منحه للغير بترخيص فرعي أو نشره أو إعادة توزيعه أو دمجه في منتج آخر. يجب الحصول على موافقة كتابية من مالك المشروع قبل إعادة استخدام الكود الأصلي.


راجع [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) لإشعارات تراخيص المكونات الخارجية.

---

## Documentation index

- [Detailed technical analysis — English](docs/TECHNICAL-ANALYSIS.md)
- [التحليل الفني التفصيلي — العربية](docs/TECHNICAL-ANALYSIS-AR.md)
- [Threat-intelligence correlation](docs/THREAT-INTELLIGENCE-CORRELATION.md)
- [Detection map](docs/DETECTION-MAP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Implementation status](docs/IMPLEMENTATION-STATUS.md)
- [Realtime monitoring](docs/REALTIME-MONITORING.md)
- [Windows validation checklist](docs/WINDOWS-VALIDATION.md)
- [Safe lab instructions](docs/SAFE-LAB-AR.md)
- [Third-party notices](THIRD-PARTY-NOTICES.md)
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

---

## English

### 1. What was analysed

The investigation focused on a multi-stage ClickFix delivery chain associated with the filenames `crandle.txt`, `Z797.ps1`, and the encrypted `tctc.bba` payload. The lure imitates a Cloudflare-style human-verification page and instructs the victim to run a command through Windows Run / Command Prompt. That is the central social-engineering trick: a legitimate CAPTCHA does not require a user to paste and execute a shell command.

The recovered chain is consistent with a TCTC / Z797 delivery path leading to a task-driven controller publicly described in the closest matching research as LegionLoader. Family naming is not fully settled: ThreatFox IOC 2031306 labels its record Stealc, while the closest delivery-chain report from Plume describes LegionLoader. This repository therefore uses **TCTC / Z797 chain** as the specific sample designation and records the public naming discrepancy rather than claiming a definitive family attribution.

The analysis was performed offline using the supplied artifacts, PE inspection, static disassembly, reconstruction/decryption of recovered stages, and review of previously captured protocol material. **No malware sample or helper was executed, and no suspected C2 or distribution host was contacted.**

### 1.1 The initial user-run command (defanged analysis)

The command supplied for this investigation is the **first user-side execution point** in the chain. It is intentionally represented below as analysis notes rather than a runnable command. The original chained shell line is not reproduced as executable text in this repository.

| Observed step | What it does | Why it matters |
|---|---|---|
| Set `__VSCMD_WIN_64BIT=true` | Creates or overwrites an environment variable in the current command shell. | It is an environment marker; by itself it is not proof that a Visual Studio toolchain is installed or being used. |
| Change directory to `%TEMP%` | Makes the user's temporary directory the working directory. | Subsequent relative paths resolve from a writable temporary location. |
| Retrieve `crandle.txt` from path token `/454` | The supplied command uses `curl.exe -sLo` to save the response under the name `crandle.txt`. | `-s` suppresses normal progress output, `-L` follows redirects, and `-o` writes the response to a file; the command shown does not perform a content-signature or hash check. |
| Retrieve `Z797.ps1` from path token `/455` | Saves a second response as `Z797.ps1` in the temporary directory. | The file is staged beside `crandle.txt`; the pasted line alone does not prove that this file was successfully downloaded or executed. |
| Interpret lines from `crandle.txt` as commands | The final `for /f` construct reads the file line-by-line and passes each line to the command interpreter for execution. | This is the critical hand-off: the downloaded text is treated as command input, not as a passive text document. The actual next action depends on the contents of `crandle.txt`. |

**Defanged sequence:** set the environment marker → move to `%TEMP%` → save responses as `crandle.txt` and `Z797.ps1` from the supplied `/454` and `/455` path tokens → pass each line from `crandle.txt` to the command interpreter. This description preserves the behavior relevant to analysis without providing a copy-and-run loader.

**Delivery-host discrepancy:** the newly supplied text contains the numeric host token `1566454788`. If interpreted as an unsigned 32-bit decimal IPv4 representation in network-byte order, it corresponds to `93.94.52.4`. Earlier local analysis records `93.94.52.29` for the initial delivery activity. These are different addresses. We retain `93.94.52.4` only as an **unconfirmed candidate derived from the newly supplied command text** and do not merge it with the previously recorded `.29` indicator without corroborating DNS, HTTP, browser, or packet-capture evidence. The command text alone does not establish a successful connection or download.

### 2. Reconstructed infection chain

```text
Fake Cloudflare / ClickFix verification page
                  |
                  v
Victim is instructed to paste and run a command
through Windows Run / Command Prompt
                  |
                  v
Initial delivery retrieves crandle.txt and Z797.ps1
from the observed delivery infrastructure
                  |
                  v
Obfuscated PowerShell stage
  - reconstructs a smaller script in memory
  - displays a fake "CloudTrust Auth" window
  - retrieves encrypted tctc.bba
                  |
                  v
Layered decryption and in-memory stages
  - recovered chain includes XTEA / AES layers
  - performs environment / anti-analysis checks
                  |
                  v
Inner task-driven controller
  - registers with its configured controller
  - receives task records
  - reports task status/results
                  |
                  v
Task-selected file, process, persistence,
Chrome-helper and dynamically supplied module paths
```

The observed initial delivery host was `93[.]94[.]52[.]29`, associated with retrieval of `crandle.txt` and `Z797.ps1`. The PowerShell stage retrieves the encrypted `tctc.bba` artifact and presents a fake authentication/verification window. Recovered stages include environment checks involving display-device information and public-IP / ASN context; a query to `ipinfo[.]io` is an anti-analysis/context indicator, not a malicious IOC by itself.

### 3. What the recovered controller can do

The inner controller is a task-driven Windows loader/backdoor component, not merely a one-time downloader. Static analysis identified the following capabilities or implemented code paths:

- **Remote tasking and reporting:** controller communication is configured around `benderoflight[.]com`, with `/nfront.php` used for registration/task retrieval and `/nback.php` for task-result reporting. The reviewed message format uses Base64 framing around RC4-transformed message bodies.
- **Payload and file tasks:** handlers support task-selected PE, shellcode, script/PowerShell-related, installer/MSI, download, write and extraction operations. The effect depends on the remote task and the payload supplied with it.
- **Multiple process-execution paths:** separate code paths target RuntimeBroker, create suspended child processes, use remote process-memory execution, create image-backed processes, and include an Explorer-associated APC path. These are distinct implementations; they should not all be described as one generic process-hollowing technique.
- **AMSI tampering attempt:** a separate path prepares short return-style stubs for `AmsiScanString` and `AmsiScanBuffer`. Static code establishes an attempt/capability, not successful modification or a proven AMSI bypass on a victim.
- **Persistence capability:** the controller contains conditional Run / RunOnce writes. The code's presence does not prove that a persistence task was sent or successfully installed on the analysed host.
- **Chrome-related key retrieval:** the reviewed build reads Chrome `Local State` key material and includes a helper path using Chrome's App-Bound decryption interface. The helper uses a permissive local named-pipe security descriptor. This is credential-access-relevant capability, but successful extraction and later upload are not established by the reviewed transaction.
- **Dynamic module framework:** the controller can dispatch task-specific methods through a custom in-memory module interface. The actual method bodies for some dynamically supplied modules were not present in the recovered evidence set, so their ultimate behavior remains unknown.

The controller's task model means that its impact can change with server-provided tasks and modules. A capability in the binary is not proof that the operator invoked it or that it succeeded on a particular endpoint.

### 4. Evidence: what is established and what is not

| Topic | Assessment from the reviewed evidence |
|---|---|
| ClickFix / fake verification delivery | **Observed in the reconstructed chain** |
| `crandle.txt`, `Z797.ps1`, encrypted `tctc.bba` stages | **Recovered / analysed artifacts** |
| Inner controller identity | **Strong hash-level link** to ThreatFox IOC 2031306's 494,080-byte controller |
| `/nfront.php` and `/nback.php` task protocol | **Recovered from static configuration and previously captured offline transaction material** |
| Multiple process execution / memory paths | **Implemented code paths identified statically**; successful execution on a victim is not proven by code alone |
| AMSI tampering | **Attempt path identified**; successful bypass is not proven |
| Run / RunOnce persistence | **Conditional capability identified**; successful installation is not proven |
| Chrome key helper | **Key-retrieval capability identified**; successful extraction and exfiltration are not proven |
| Five task filenames in one reviewed response | `42.bin` was available for review; the other four files were not in the reviewed evidence set |
| Credential theft, cookie theft or upload | **Not established** by the available transaction evidence |
| Ransomware, mass encryption/wiping, conventional keylogging, webcam/microphone capture | **Not established** in the recovered core controller |

These are evidence boundaries, not guarantees that a capability could never be delivered later. Some module bodies and task payloads were unavailable. The first transformation from raw `tctc.bba` was also not fully reproducible from the supplied material. A saved disassembly provides broad byte coverage of the recovered controller, but not a manual semantic classification of every function.

### 5. Recovered sample fingerprints

The hashes below are included for defensive identification and cross-checking. **No malware samples, reconstructed executable payloads, or PCAP payload files are distributed in this repository.**

| Artifact | Size | SHA-256 |
|---|---:|---|
| Original outer PE | 8,147,456 bytes | `077c93f044b590a017771ced5067e8adde18d629598ea545496904dafcfd8e22` |
| Raw `tctc.bba` delivery artifact | 8,178,288 bytes | `c34719ff34d037eedc4338655d844734a7451c00250a56c8cba8f807f92bcafb` |
| Recovered stage-2 shellcode | 8,328,272 bytes | `ce9263eec902131910d6ff69b33f2d61f09707dadb7818c11de46d97fa441169` |
| Generated stage-3 PE | 8,324,608 bytes | `30a16519c20df8f6d7fd8e127c5e2ba688b074eb723c60ed88e36b1da3cc1b12` |
| Inner controller | 494,080 bytes | `a10e4fbff548ea2839db1cac5faaa3316b950cc9f8a2cf82658b1a9ad7eb9089` |
| `42.bin` encrypted transfer copy (offline capture) | 736,768 bytes | `4dd38c86f35b68702d47d3bb90c8dc694e9b85d179b0825fb1aea05d3e60a335` |
| `42.bin` decrypted PE (offline analysis) | 736,768 bytes | `4a5e0ed88529761af8e86afcf2b969217a7345abe2c467523d036bb5126ca644` |

### 6. Indicators of compromise (defanged)

These are historical indicators observed in the analysed chain. They may be stale, reused, incomplete, or shared with related activity. Do not block an IP or domain solely because it appears in this table; correlate process identity, time, path, and other evidence first.

| Indicator | Role / confidence note |
|---|---|
| `93[.]94[.]52[.]29` | Initial delivery host associated with `crandle.txt` / `Z797.ps1` in the analysed chain |
| `1566454788` → `93[.]94[.]52[.]4` (provisional) | Decimal-IPv4 interpretation of the host token in the newly supplied initial command; uncorroborated and distinct from `93[.]94[.]52[.]29` |
| `benderoflight[.]com` | Recovered inner-controller domain |
| `hxxps://benderoflight[.]com/nfront.php` | Registration / task retrieval path |
| `hxxps://benderoflight[.]com/nback.php` | Task-result reporting path |
| `survivomatic[.]com` | Host associated with the `42.bin` task in the reviewed response |
| `ruthaiv[.]com` | Host associated with other task files in the reviewed response |
| `ipinfo[.]io` | Public-IP / ASN environment check; contextual only, not malicious by itself |
| `109[.]238[.]86[.]137` | Destination in the locally reviewed TLS transaction; shared/reused infrastructure has also been reported, so an IP-only match is not unique proof of this infection |

The controller returned five task filenames in the reviewed transaction: `42.bin`, `eeGai2ahyae.bin`, `awpg2gawa2.fjk`, `1488.bin`, and `just_test.bin`. Only `42.bin` was available in the evidence set reviewed here; the other four payloads remain unknown. Do not infer their purpose from filenames.

### 7. Public research and attribution

The closest public match for this delivery chain is Plume Security Lab's **“Before GTA VI”** (18 November 2026), which describes fake Cloudflare ClickFix instructions, `crandle.txt`, `Z797.ps1`, encrypted `tctc.bba`, and the related controller paths. ThreatFox / abuse.ch **IOC 2031306** records the `benderoflight[.]com/nfront.php` endpoint and the same 494,080-byte controller hash, but its malware-family metadata labels the IOC Stealc. The family label discrepancy is retained here.

Other reporting is used only as family/platform context, not as a source for importing unrelated IOCs:

- [Plume Security Lab — Before GTA VI](https://www.plume.com/newsroom/before-gta-vi) — closest public delivery-chain match.
- [ThreatFox / abuse.ch — IOC 2031306](https://threatfox.abuse.ch/ioc/2031306/) — controller hash / endpoint correlation; family tag differs.
- [eSentire TRU — ROMULUS ClickFix to LegionLoader and Warden Stealer](https://www.esentire.com/blog/romulus-clickfix-to-legionloader-and-warden-stealer-breaking-down-a-multi-stage-malware-intrusion) — related but separate intrusion chain; not proof of Warden delivery in this case.
- [AhnLab ASEC — ClickFix-delivered LegionLoader](https://asec.ahnlab.com/en/95374/) — family-level context; separate infrastructure.
- [Forescout Vedere Labs — ROMULUS](https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/) — related multi-payload delivery platform; not the same sample profile.

For the detailed reverse-engineering notes, subtype distinctions, references, and confidence boundaries, see [`docs/TECHNICAL-ANALYSIS.md`](docs/TECHNICAL-ANALYSIS.md) and [`docs/TECHNICAL-ANALYSIS-AR.md`](docs/TECHNICAL-ANALYSIS-AR.md). For source provenance and related-campaign separation, see [`docs/THREAT-INTELLIGENCE-CORRELATION.md`](docs/THREAT-INTELLIGENCE-CORRELATION.md).

### 8. What Guardian checks

Guardian is deliberately scoped to the locally analysed TCTC / Z797 profile. It is not intended to detect every ClickFix, LegionLoader, infostealer, or Windows threat.

| Area | Targeted investigation |
|---|---|
| Running processes | Process inventory, image paths, and exact recovered payload identity / supported actor-side correlation |
| Live memory | Read-only inspection of the fixed target allow-list: `RuntimeBroker.exe`, `explorer.exe`, `chrome.exe`, and `csc.exe` only when it runs from the analysed staging tree |
| Staging files | The two analysed roots: `%TEMP%\Local` and `%WINDIR%\Temp\Local`; exact artifact hashes, sizes, names and recovered content markers |
| Persistence | Z797-linked Run / RunOnce values, Startup items, services and scheduled-task actions; selected WMI event history |
| Network | Local DNS cache, Hosts mappings and active endpoints; promotion requires exact Z797 context and process attribution |
| Event history | Available Sysmon, Windows Security, PowerShell 4103/4104, Task Scheduler and WMI records containing Z797 indicators or complete actor-side correlation |
| Continuous monitoring | Selected checks and future telemetry while Guardian remains open or minimized to the tray |

Unrelated browser profile content, browser history, generic Temp files, broad endpoint reputation, Windows Defender alerts, sibling-campaign IOCs, and unrelated process anomalies are outside the active sample profile.

### 9. Memory scanner: real work and boundaries

The memory collector is an implemented **read-only Windows API path**, not a status-only placeholder. For the fixed target allow-list, it:

- Opens eligible process handles with query and read-only memory rights.
- Walks virtual-memory regions using `VirtualQueryEx` (metadata enumeration, not a byte scan).
- Uses targeted `ReadProcessMemory` reads to inspect selected executable private regions and probe for minimally valid PE headers.
- Uses `QueryWorkingSetEx` to identify resident executable image pages that have become private / copy-on-write; this is a signal, not proof of maliciousness.
- Enumerates threads and modules with Toolhelp snapshots and queries thread start addresses with `NtQueryInformationThread` where access permits.
- Inspects the known `AmsiScanString` and `AmsiScanBuffer` exports when `amsi.dll` is present and readable.
- Reports API-call counts, regions, targeted bytes read, per-process results, and access gaps in the investigation report.

It does **not** dump every process or scan every byte of memory. Protected processes, access restrictions, cross-bitness boundaries, short-lived activity and unsupported telemetry can reduce visibility. A private executable region, copy-on-write page, process name, or AMSI-related observation alone is not proof of Z797 infection. Guardian does not write to another process's memory, patch code, queue APCs, or inject threads.

### 10. Response and containment boundaries

Guardian offers a cleanup action only when it can revalidate a current target. Depending on the evidence and user confirmation, supported actions include:

- Quarantine a verified sample artifact after rechecking its path, regular-file status, exact size and SHA-256.
- Stop only a verified live process whose image is an exact recovered payload and whose process identity is pinned/rechecked.
- Back up and remove only an exact Z797 Run / RunOnce value.
- Back up and disable only a scheduled task or service whose current action still contains an exact Z797 command/artifact reference.
- Back up Hosts and remove only an exact built-in Z797 mapping.
- Offer a narrowly scoped outbound Firewall rule only when an exact payload identity is correlated with a confirmed address and the user approves it.

Historical event records, DNS-cache observations, RunMRU history, generic memory anomalies, process names, and IP-only matches are evidence—not cleanup targets. Guardian does not wipe browser data, clear the entire DNS cache, delete unrelated Temp files, or erase event logs. Automatic containment is restricted to exact recovered file SHA-256 + byte size + analysed path + verified live process identity.

### 11. Sysmon and safe validation

Sysmon is obtained from Microsoft's official distribution endpoint at runtime and checked before use. The default configuration is **Event 29 detect-only**. Guardian does not enable Event 27 PE creation blocking and does not block new executable files. Standalone Sysmon installation requires the normal Windows elevation and license-acceptance flow. See [`docs/SYSMON-REQUIRED.md`](docs/SYSMON-REQUIRED.md).

For a safe local check, run `Run-Safe-Z797-Lab.bat`, perform a scan, inspect `[LAB]` / `Info` findings, and optionally test manual quarantine on the inert text canary. The lab creates a text-only file with static marker strings and invokes a harmless `cmd.exe` echo process to generate ordinary process/file telemetry when Sysmon is available. It does not perform injection, AMSI tampering, persistence, credential access, network communication, C2 requests, or remote-memory modification. Run `Cleanup-Safe-Z797-Lab.bat` afterward. Full instructions and limitations are in [`docs/SAFE-LAB-AR.md`](docs/SAFE-LAB-AR.md).

### 12. Run from source

Requirements: supported Windows 11 / Windows Server 2019+ system, Python 3.11+, and Administrator approval when sensor installation or system remediation requires it.

```powershell
python -m pip install -r requirements.txt
python src/main.py
```

Or run `Run-TCTC-Guardian.bat`. The first-run Sysmon flow uses the regular Windows UAC prompt and asks for acceptance of the Microsoft Sysinternals license when standalone installation is needed.

### 13. Validation status and limitations

The source package was prepared and checked in a non-Windows Linux environment. The portable suite uses fixtures and mocks for Windows-specific behavior. The recorded preparation checks are 252 unit tests, Python compilation, `--self-check`, safe-lab lifecycle tests, Sysmon XML policy validation, and ZIP integrity checks.

These checks do **not** substitute for Windows integration testing. The preparation environment did not execute WinTrust, UAC, Sysmon service/driver installation, native Event Log subscriptions, real process-memory reads, Registry / task / service / Firewall remediation, PySide6 GUI/tray rendering, DPI behavior, or Nuitka Windows packaging. Complete [`docs/WINDOWS-VALIDATION.md`](docs/WINDOWS-VALIDATION.md) on a disposable supported Windows system before relying on live response or distributing a binary.

Other deliberate limitations:

- No full-disk scan, kernel driver, universal API hook, or guaranteed pre-execution block.
- Continuous monitoring stops when the app exits; Guardian is not a persistent Windows service.
- Historical event visibility depends on providers, audit settings, retention and permissions having been available before the incident.
- Unknown dynamic modules and future task URLs outside the recovered profile cannot be inferred from the static indicators.
- A clean targeted scan is not proof of full eradication. Confirmed execution with unresolved process compromise or persistence should be handled as a security incident; preserve evidence and consider trusted rebuild procedures.

### 14. Repository documentation

- [`docs/TECHNICAL-ANALYSIS.md`](docs/TECHNICAL-ANALYSIS.md) — detailed English reverse-engineering report.
- [`docs/TECHNICAL-ANALYSIS-AR.md`](docs/TECHNICAL-ANALYSIS-AR.md) — detailed Arabic analysis.
- [`docs/THREAT-INTELLIGENCE-CORRELATION.md`](docs/THREAT-INTELLIGENCE-CORRELATION.md) — separates the exact chain from related campaigns.
- [`docs/DETECTION-MAP.md`](docs/DETECTION-MAP.md) — behavior-to-detection and response mapping.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — component architecture and deliberate capability gaps.
- [`docs/IMPLEMENTATION-STATUS.md`](docs/IMPLEMENTATION-STATUS.md) — implemented functionality and guardrails.
- [`docs/REALTIME-MONITORING.md`](docs/REALTIME-MONITORING.md) — live monitoring sources and limits.
- [`docs/WINDOWS-VALIDATION.md`](docs/WINDOWS-VALIDATION.md) — required Windows integration checklist.
- [`docs/SAFE-LAB-AR.md`](docs/SAFE-LAB-AR.md) — safe canary instructions in Arabic.
- [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) — third-party components and notices.
- [`SECURITY.md`](SECURITY.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md) — vulnerability reporting and contribution guidance.

### 15. Third-party notices and operating-system interfaces

TCTC Guardian Z797 is built with the following third-party components and operating-system interfaces:

- **Python** — PSF License. See the [Python license](https://docs.python.org/3/license.html).
- **PySide6 / Qt for Python** — licensing depends on the selected modules and distribution model. Review the [official licensing notes](https://doc.qt.io/qtforpython-6/licenses.html) before distributing a binary.
- **watchdog** — Python filesystem notification package; review its bundled license metadata when producing a distribution.
- **Nuitka** — optional build tool: [official website](https://nuitka.net/).
- **Microsoft Sysmon** — downloaded from Microsoft's official endpoint at runtime; it is not bundled or redistributed in this source package. Review the [Sysinternals license terms](https://learn.microsoft.com/en-us/sysinternals/license-terms) and [license FAQ](https://learn.microsoft.com/en-us/sysinternals/license-faq).
- **Windows APIs / Event Log / Task Scheduler / Registry / Firewall interfaces** — built-in operating-system interfaces; no external vendor SDK is bundled for these APIs.

For the maintained notices file, see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

### 16. Project rights and license status
**Copyright © 2026 Jo0X01. All rights reserved.**

[`LICENSE.md`](LICENSE.md)

Official project repository:
[github.com/Jo0X01/TCTC-Guardian-Z797](https://github.com/Jo0X01/TCTC-Guardian-Z797).


**The original TCTC Guardian Z797 project code is not offered under the GNU General Public License or any other open-source license. All rights are reserved.** No permission to copy, modify, sublicense, publish, redistribute, or incorporate the project code into another product is granted by making this repository public. Obtain written permission from the project owner before reusing the original project code.

Licenses belonging to third-party components (for example Python, Qt/PySide6, and watchdog) apply only to those respective components. They do not grant a license to the original TCTC Guardian Z797 code. Microsoft Sysmon is downloaded separately from Microsoft and is not included in this repository.


See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for component-specific notices.