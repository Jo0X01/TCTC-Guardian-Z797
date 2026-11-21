> **Historical engineering notes:** This document preserves pre-public-release analysis and development context. Older version numbers below refer to internal development snapshots, not public GitHub releases.

# ملخص التحليل الفني لسلسلة TCTC / LegionLoader

**تاريخ المراجعة:** 21 نوفمبر 2026  
**النظام المستهدف:** Windows x64  
**نوع التحليل:** تحليل ساكن، تفكيك بنية PE، مراجعة تدفق البيانات، وفك طبقات موجودة مسبقًا في الأدلة دون تشغيل العينة أو الاتصال بسيرفراتها.

## الخلاصة

العينة التي راجعناها جزء من سلسلة إصابة تبدأ بخدعة ClickFix. صفحة مزيفة تشبه تحقق Cloudflare تطلب من المستخدم فتح Run أو CMD ولصق أمر من الحافظة. الأمر ينزّل `crandle.txt` و`Z797.ps1` من عنوان IP معروف في هذه الحملة، ثم يقوم PowerShell المخفي بتنزيل `tctc.bba` وفك مراحله وتحميل كود إضافي في الذاكرة.

المرحلة الداخلية التي استطعنا استعادتها ليست مجرد Downloader. إنها Controller يستقبل أوامر من خادم بعيد، ويمكنه تشغيل ملفات PE وShellcode وPowerShell وMSI، والتعامل مع عمليات أخرى، وكتابة إعدادات تشغيل تلقائي، وتشغيل وحدات إضافية من الذاكرة. كما يحتوي على مسارات مرتبطة بمفاتيح تشفير Chrome.

أقوى رابط لتعريف العينة هو تطابق SHA-256 للـController الداخلي، حجمه 494,080 بايت، مع السجل التحليلي في ThreatFox IOC 2031306. الاتصال المعروف يستخدم `benderoflight[.]com` مع `/nfront.php` لجلب المهام و`/nback.php` لإرسال نتائجها. تقرير Plume المنشور في 18 نوفمبر 2026 يصف سلسلة ClickFix نفسها تقريبًا وملف `tctc.bba` ومسارات C2 ذاتها.

توجد ملاحظة تسمية: ThreatFox يضع في خانة Malware اسم Stealc، بينما Plume وتقارير أخرى تربط السلسلة بـLegionLoader. لذلك نستخدم هنا وصف **TCTC / LegionLoader chain** مع توضيح اختلاف التصنيف، ولا نفترض أن Stealc أو أي Infostealer آخر تم تثبيته بنجاح على الجهاز الذي تمثل أدلته هذه المعاملة.

## ما الذي يحدث أثناء الإصابة؟

1. صفحة مزيفة تقلّد Cloudflare وتطلب تنفيذ أمر Windows يدويًا.
2. يتم تنزيل `crandle.txt` و`Z797.ps1` من `93[.]94[.]52[.]29`.
3. PowerShell مخفي يعرض نافذة تحقق مزيفة ويحصل على `tctc.bba`.
4. تمر الحمولة بمراحل فك تشفير وتحميل داخل الذاكرة، مع فحوصات لاسم كرت الشاشة ونوع ASN عبر `ipinfo[.]io` لاكتشاف بيئات التحليل والاستضافة.
5. يبدأ Controller يتصل بـ`benderoflight[.]com` ويستقبل أوامر وملفات من السيرفر.

## قدرات Controller المؤكدة من الكود

- تشغيل PE وShellcode وPowerShell ومسارات MSI.
- مسار Type 1 / subtype `0x0A` لإنشاء RuntimeBroker معلّق، وتجهيز PE ومحمّل يدوي داخل العملية ثم تحويل مسار الخيط الأساسي إليه. لا يوجد في السلسلة التي راجعناها ما يثبت أنه Process Hollowing تقليدي.
- مسار Type 1 / subtype `0x0B` للتعامل مع عملية فرعية عبر تخصيص وكتابة الذاكرة وتغيير الحماية وإنشاء خيط؛ لا نخلطه بمسار RuntimeBroker السابق.
- مسار Type 1 / subtype `0x11` يتبع تسلسلًا قريبًا من Process Ghosting: ملف مؤقت، ثم Delete-Pending، ومحاولة كتابة PE، وإنشاء SEC_IMAGE، ثم إنشاء عملية من الـSection. هذا استنتاج ساكن؛ نجاح كل الاستدعاءات على Windows غير مثبت، كما توجد ملاحظة توثيقية من Microsoft حول I/O بعد تعليم الملف للحذف.
- مسار منفصل Type 1 / subtype `0x12` لإنشاء عملية native مرتبطة بصورة ملف.
- مسار APC مرتبط بعملية Explorer جديدة، مستقل عن مساري RuntimeBroker وGhosting.
- مسار Type 4 يحضّر تعديلات على `AmsiScanString` و`AmsiScanBuffer`؛ وجود الكود يثبت محاولة/قدرة، لا نجاح تجاوز AMSI على جهاز مصاب.
- كتابة قيم Run وRunOnce وفقًا للمهام المستلمة.
- إطار Plugins داخل الذاكرة يقرأ Metadata للمكتبات ويحل Imports ويستدعي Methods بمعرّفات رقمية. أجسام بعض هذه الـMethods غير موجودة في العينة التي استعدناها، لذلك لا يمكن الجزم بوظيفتها النهائية.

## Chrome ومفاتيح التشفير

وجدنا مسارين متعلقين بـChrome. الأول يقرأ `os_crypt.encrypted_key` من نسخة `Local State` موجودة في مسار Staging مؤقت، ويفك Base64 ثم يتجاوز بادئة `DPAPI`؛ لم نجد في الدالة التي راجعناها استدعاء `CryptUnprotectData`، ولذلك لا نصف الناتج كمفتاح Plaintext مؤكد.

المسار الثاني يشغّل Chrome كعملية معلّقة ويحمّل Helper يستخدم `IElevator2Chrome::DecryptData` لمحاولة الحصول على مفتاح App-Bound بطول 32 بايت، ثم يعيد النتيجة عبر Named Pipe ويكتبها إلى مسار يحدده الـTask. لاحظنا أن ACL للـPipe هو `D:(A;;GA;;;WD)`، أي صلاحية Generic-All لمجموعة World/Everyone إذا عُرف اسم الـPipe.

لكننا **لم نثبت** أن بيانات المفتاح الناتجة انتقلت إلى جسم POST المرسل إلى `/nback.php`. لا يوجد في تدفق البيانات الذي راجعناه رابط مباشر يثبت ذلك. كذلك لم يظهر في جدول API الثابت الذي راجعناه ما يثبت وجود Keylogger تقليدي أو تسجيل شاشة أو كاميرا أو ميكروفون. هذا لا ينفي وظائف قد تأتي في Modules ديناميكية لم تكن متاحة لنا.

## ما لا نستطيع تأكيده

- لا يوجد دليل كافٍ على سرقة كلمات مرور أو Cookies أو جلسات متصفح في المعاملة التي راجعناها.
- لا يوجد إثبات على رفع Chrome keys إلى C2.
- أربعة من الملفات الخمسة التي أرجعها C2 لم تكن موجودة ضمن الأدلة المتاحة، لذلك محتواها غير معروف.
- لا نستطيع إثبات نجاح كل عمليات الحقن أو APC أو Ghosting أو AMSI أو تنفيذ أي Task لم نشاهد أثره.
- لم نجد مسار Ransomware أو تشفير جماعي للملفات في المراحل التي راجعناها.
- لا يعني اكتمال التفكيك الخطي لقسم `.text` أننا فهمنا دلاليًا كل Function؛ ما زال هناك 1,600 سجل Runtime Function وبعض الـMethods الديناميكية غير المحللة.

## المصادر الحديثة التي راجعناها

- **20 نوفمبر 2026 — eSentire:** [ROMULUS ClickFix to LegionLoader and Warden Stealer](https://www.esentire.com/blog/romulus-clickfix-to-legionloader-and-warden-stealer-breaking-down-a-multi-stage-malware-intrusion). حملة مختلفة في مرحلة التوصيل تعتمد على MSI، لكنها توثق LegionLoader وبروتوكول `nfront.php` / `nback.php` وتذكر `benderoflight[.]com` ضمن بنية C2 مرصودة. استخدمناها كسياق داعم فقط.
- **18 نوفمبر 2026 — Plume Security Lab:** [Before GTA VI](https://www.plume.com/newsroom/before-gta-vi). أقرب تقرير عام للسلسلة التي حللناها: ClickFix، `crandle.txt`، `Z797.ps1`، `tctc.bba`، فحوصات البيئة ومسارات LegionLoader.
- **16 نوفمبر 2026 — ThreatFox IOC 2031306:** [السجل التحليلي](https://threatfox.abuse.ch/ioc/2031306/). يذكر عنوان `/nfront.php` وHash الـController المطابق.
- **15 أكتوبر 2026 — Forescout Vedere Labs:** [ROMULUS ClickFix delivery platform](https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/). سياق أوسع لتطور حملات ClickFix، وليس إثباتًا بأن كل مؤشرات ROMULUS تنتمي إلى عينتنا.
- **3 سبتمبر 2026 — AhnLab ASEC:** [LegionLoader distributed via ClickFix](https://asec.ahnlab.com/en/95374/). تحليل سابق لقدرات LegionLoader العامة ومسارات معلومات Chrome.

## أثر ذلك على الأداة

الإصدار `v0.8.2` يتضمن محرك فحص ذاكرة حي Read-only يفحص مناطق التنفيذ الخاصة، وPE headers، وعناوين بداية الـThreads، وصفحات Copy-on-Write، والـAMSI stubs المحددة، مع التقاط الأدلة وحساب SHA-256 واحتواء العملية بالكامل عند استيفاء شروط الثقة وبعد الموافقة. كما أصبحت قراءة الملفات والـHash والبحث عن العلامات Streaming من غير حد اعتباطي لعدد الملفات أو حجمها.

ما زالت خدمة Windows الدائمة، واسترجاع تاريخ APC injection، والمقارنة الكاملة لكل Module، وتحديثات Threat Profiles الموقعة، ومحرك القواعد المخصصة غير مكتملة. فحص الذاكرة الحالي لا يكتب إلى ذاكرة العمليات؛ واحتواء الذاكرة ينهي العملية بالكامل بعد حفظ الدليل والموافقة، لأنه لا توجد طريقة عامة وآمنة لإيقاف صفحة تنفيذ منفردة داخل عملية قد تكون حالتها الداخلية غير مستقرة. صفحة Memory والإعدادات تعرض الحالة بوضوح ولا تدّعي تشغيل هذه المستشعرات. راجع `docs/IMPLEMENTATION-STATUS.md` للتفاصيل.

## التقييم النهائي

الـController الداخلي Backdoor/Loader قابل لتلقي مهام عن بُعد، وله مسارات تشغيل وتنفيذ داخل عمليات أخرى، وPersistence، وملفات، ووحدات ديناميكية، ووظائف متعلقة بمفاتيح Chrome. لذلك فإن التشغيل المؤكد لهذه السلسلة يستدعي التعامل معه كحادث أمني مرتفع الخطورة: عزل الجهاز، حفظ الأدلة، فحص العمليات والـPersistence، استخدام أدوات موثوقة، وتغيير كلمات المرور وإلغاء الجلسات من جهاز نظيف كإجراء احترازي. لا يجب ادعاء سرقة بيانات مؤكدة أو تنظيف كامل دون أدلة إضافية.
