import "math"

/*detects files with entropy between 5.5 and 6.5*/
rule LowEntropy
{
    condition:
        math.entropy(0, filesize) >= 5.5 and math.entropy(0,filesize) < 6.5 
}
