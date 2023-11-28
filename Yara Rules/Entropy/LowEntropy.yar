import "math"

/*detects files with entropy less than 4.5*/
rule LowEntropy
{
    condition:
        math.entropy(0, filesize) < 4.5
}
