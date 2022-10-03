#pragma once
#include <string>
#include <vector>
#include <unordered_map>

using namespace std;


class ScoreText
{
public:
	ScoreText(const char* file);
	double checkFitness(string &text) const;
	string getAlphabet() const;

private:
	string defaultAlphabet;
	vector<int> ngrams;
	size_t ngramLength;
	unsigned int bitmask{ 0 };
	unordered_map<char, int> map;
};