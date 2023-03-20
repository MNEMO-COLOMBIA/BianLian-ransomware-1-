rule BianLian_Ransomware
{
    meta:
        description = "Detects BianLian Ransomware"
        author = "fevar54"
        reference = "https://www.openanalysis.net/2021/10/21/bianlian-ransomware-attack/"

    strings:
        $s1 = "BianLian" wide
        $s2 = ".BianLian" wide
        $s3 = "CRIMSON" wide
        $s4 = "BLACKHAT" wide

    condition:
        all of ($s*) and
        any of (filesize < 5MB, filesize > 100KB)
}
