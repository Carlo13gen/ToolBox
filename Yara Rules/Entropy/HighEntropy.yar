import "math"

/*detects files with entropy greater than 7.5*/
rule LowEntropy
{
    condition:
        math.entropy(0, filesize) >= 7.5
}
