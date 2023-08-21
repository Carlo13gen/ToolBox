rule I_LOVE_YARA
{
    meta:
        author = "Carlo Iurato"
        date = "21/08/2023"
        version = "0.1"
        exercise = "write a yara rule that can find itself"
    strings:
        $a = "I love YARA"
    condition:
        any of them
}