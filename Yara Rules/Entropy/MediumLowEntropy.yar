import "math"

/*detects files with entropy between 4.5 and 5.5*/
rule LowEntropy
{
    condition:
        math.entropy(0, filesize) >= 4.5 and math.entropy(0,filesize) < 5.5 
}
