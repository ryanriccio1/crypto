#pragma once
#include <string>
#include "scoreText.h"

using namespace std;

class PlayfairCrack
{
public:
    string file;
    string ciphertext;
    string bestKey = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
    double maxFitness{ 0 };

    PlayfairCrack(const char* file);
    const char* crack(const char* newCiphertext, int iterations = 10000, float temp = 30.0,
        float step = 0.2, float fudgeFactor = 0.5, float threshold = 95);

    string playfairDecrypt(string &key) const;
    void modifyKey(string& key) const;

private:
    void exchange2letters(string &key) const;
    void swap2rows(string &key) const;
    void swap2cols(string &key) const;
    void swapAllCols(string& key) const;
    void swapAllRows(string& key) const;
    void removeQs(string& plaintext) const;
};