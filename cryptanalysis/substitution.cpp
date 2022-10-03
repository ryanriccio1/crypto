#include <vector>
#include <unordered_map>
#include <string>
#include <iostream>
#include <random>
#include <ctime>
#include <algorithm>
#include "include/rriccio/substitution.h"
#include "include/rriccio/scoreText.h"

using namespace std;

SubstitutionCrack::SubstitutionCrack(const char* filename)
{	// set seed and get file as std::string
	srand(static_cast<unsigned int>(time(0)));
	file = string(filename);
}

const char* SubstitutionCrack::crack(const char* newCiphertext, int iterations, int threshold)
{
	auto score = ScoreText(file.c_str());
	string tmpText = "";
	ciphertext = newCiphertext;
	alphabet = score.getAlphabet();

	// get only characters that are in our alphabet
	for (char current_char : ciphertext)
	{
		if (alphabet.find(toupper(current_char)) != string::npos)
			tmpText += toupper(current_char);
	}

	// process inputs
	ciphertext = tmpText;
	fillMap(score.getAlphabet());
	for (auto& character : alphabet)
	{
		bestKey.push_back(binValues[character]);
	}
	convertCipherToBin();
	getCharPositions();

	auto rng = default_random_engine{};

	vector<int> currentKey = bestKey;
	int maxKeyHit{ 0 };
	double currentFitness{ 0 };

	// use hill climbing as described in practicalcryptography.com to find key
	for (int i{ 0 }; i < iterations; i++)
	{	// shuffle the key and check the fitness
		std::shuffle(std::begin(currentKey), std::end(currentKey), rng);
		currentFitness = hillClimb(currentKey, score);
		// keep only better kets
		if (currentFitness > maxFitness)
		{
			maxFitness = currentFitness;
			maxKeyHit = 1;
			bestKey = currentKey;
		}
		else if (currentFitness == maxFitness)
		{	// once we get the same key after 3 hill climbs, leave
			maxKeyHit++;
			if (maxKeyHit == threshold)
				break;
		}
		string plainKey = "";
		for (auto& idx : bestKey)
		{
			plainKey += charValues.at(idx);
		}
		cout << '\r' << plainKey << '\t' << maxFitness;
	}
	cout << endl;
	string decryptString;
	int idx;
	// decrypt and return
	for (auto& charIDX : cipherBin)
	{
		for (int i{ 0 }; i < bestKey.size(); i++)
		{
			if (charIDX == bestKey[i])
				decryptString += charValues.at(i);
		}
	}
	const char* cDecrypted = decryptString.c_str();
	return cDecrypted;
}

double SubstitutionCrack::hillClimb(vector<int>& key, ScoreText& score)
{
	vector<int> plaintext;
	vector<int> curVec;
	for (auto idx : cipherBin)
		plaintext.push_back(key[idx]);

	double localMaxFitness{ 0 };
	double currentFitness{ 0 };
	string plainString;
	bool betterKey = true;
	int ch1, ch2;
	while (betterKey)
	{
		betterKey = false;
		for (int i{ 0 }; i < key.size() - 1; i++)
		{
			for (int j{ i + 1 }; j < key.size(); j++)
			{	// get 2 chars in the key
				ch1 = key[i];
				ch2 = key[j];

				// swap all positions of 1 char with the other
				curVec = charPositions.at(ch1);
				for (auto& idx : curVec)
					plaintext[idx] = j;

				curVec = charPositions.at(ch2);
				for (auto& idx : curVec)
					plaintext[idx] = i;

				// convert back to plaintext
				plainString = "";
				for (auto& idx : plaintext)
				{
					plainString += charValues.at(idx);
				}
				// score
				currentFitness = score.checkFitness(plainString);
				
				// if swap was better, swap in the key and try again
				if (currentFitness > localMaxFitness)
				{
					betterKey = true;
					localMaxFitness = currentFitness;
					key[i] = ch2;
					key[j] = ch1;
				}
				else
				{	// if swap was not good, switch chars back and return
					// to main part
					curVec = charPositions.at(ch1);
					for (auto& idx : curVec)
						plaintext[idx] = i;

					curVec = charPositions.at(ch2);
					for (auto& idx : curVec)
						plaintext[idx] = j;
				}
			}
		}
	}
	// will only return once we have hit our local maximum after trying all keys
	return localMaxFitness;
}

void SubstitutionCrack::convertCipherToBin()
{	// get indexes for each char in cipher
	for (auto& character : ciphertext)
	{
		cipherBin.push_back(binValues.at(toupper(character)));
	}
}

void SubstitutionCrack::fillMap(string newAlphabet)
{	// fill translation tables for use later
	alphabet = newAlphabet;
	for (int i{ 0 }; i < alphabet.length(); i++)
	{
		charValues[i] = alphabet[i];
		binValues[alphabet[i]] = i;
	}
}

void SubstitutionCrack::getCharPositions()
{	// store positions of each type of character
	vector<int> currentVector;
	for (int i{ 0 }; i < alphabet.length(); i++)
	{
		currentVector.clear();
		for (int j{ 0 }; j < ciphertext.length(); j++)
		{
			if (cipherBin[j] == i)
			{
				currentVector.push_back(j);
			}
		}
		charPositions[i] = currentVector;
	}
}

#ifndef __cplusplus
extern "C"
{	// make callable from C
	const char* crack(const char* filename, const char* newCiphertext, int iterations, int threshold)
	{
		SubstitutionCrack cracker = SubstitutionCrack(filename);
		return cracker.crack(newCiphertext, iterations, threshold);
	}
}
#endif