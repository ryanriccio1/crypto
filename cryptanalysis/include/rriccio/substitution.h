#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include "scoreText.h"

using namespace std;

class SubstitutionCrack
{
public:
	SubstitutionCrack(const char* filename);
	const char* crack(const char* newCiphertext, int iterations = 2000, int threshold = 3);
private:
	double hillClimb(vector<int>& key, ScoreText& score);
	string ciphertext;
	string file;
	vector<int> bestKey;
	string alphabet;
	double maxFitness;
	vector<int> cipherBin;
	unordered_map<int, vector <int>> charPositions;
	unordered_map<char, int> binValues;
	unordered_map<int, char> charValues;

	void convertCipherToBin();
	void fillMap(string alphabet);
	void getCharPositions();
};