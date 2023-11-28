import "math"

/*detects files with entropy between 6.5 and 7.5*/
rule LowEntropy
{
    condition:
        math.entropy(0, filesize) >= 6.5 and math.entropy(0,filesize) < 7.5 
}
