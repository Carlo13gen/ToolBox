import "math"

/*detects files with entropy less or equal than 4*/
rule low_entropy 
{
    condition:
        math.entropy(0, filesize) <= 4.5
}
