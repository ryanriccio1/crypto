#include <string>
#include <fstream>
#include <vector>
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include "include/rriccio/scoreText.h"
#include "include/nlohmann/json.hpp"

using namespace std;
using json = nlohmann::json;

ScoreText::ScoreText(const char* file)
{   // read file and parse json
	std::ifstream f(file);
	json data = json::parse(f);

    // add ngrams to vector
	for (auto& elem : data["ngrams"])
		ngrams.push_back(elem);

    // generate bitmask based on ngram length
    ngramLength = data["ngram_length"];
    for (size_t i{ 0 }; i < (ngramLength - 1) * 5; i++)
    {
        bitmask = (bitmask << 1) + 1;
    }

    // create a map of uppercase letters to indexes
    defaultAlphabet = data["alphabet"];
    transform(defaultAlphabet.begin(), defaultAlphabet.end(), defaultAlphabet.begin(), ::toupper);

    for (int i{ 0 }; i < defaultAlphabet.length(); i++)
    {
        map[defaultAlphabet[i]] = i;
    }
}

double ScoreText::checkFitness(string& text) const
{
    double fitness{ 0 };
    size_t numCounted{ 0 };
    unsigned int ngramIdx{ 0 };
    
    // find index to convert text to only readable characters
    string tmpText = "";
    for (char current_char : text)
    {
        if (defaultAlphabet.find(toupper(current_char)) != string::npos)
            tmpText += toupper(current_char);
    }
    text = tmpText;

    // each ngram is actually the index of the score of a given ngram
    // we can have at most 32 letters, so shift by 5 and get index of the letter
    // add the first few so we have the start of the index before we continue down the string
    for (size_t idx{ 0 }; idx < ngramLength - 1; idx++)
    {
        ngramIdx = (ngramIdx << 5) + map.at(toupper(text[idx]));
    }

    for (size_t idx{ ngramLength - 1 }; idx < text.length(); idx++)
    {   // remove anything that is not in the current index, shift the old index 5bits and add the new index
        ngramIdx = ((ngramIdx & bitmask) << 5) + map.at(toupper(text[idx]));
        fitness += ngrams[ngramIdx];
        numCounted++;
    }
    // divide by 10 so we get values centered at 100 (we can store ints if we multiply by 10 in ngram generation).
    return fitness / numCounted / 10;
}

string ScoreText::getAlphabet() const
{
    return defaultAlphabet;
}

#ifndef __cplusplus
extern "C"
{   // allow C callable
    double checkFitness(const char* text, const char* file)
    {
        ScoreText fitChecker = ScoreText(file);
        string newText = string(text);
        return fitChecker.checkFitness(newText);
    }
}
#endif
