#include <string>
#include <ctime>
#include <algorithm>
#include <cmath>
#include <vector>
#include <iostream>
#include <mutex>
#include <thread>
#include "include/rriccio/playfair.h"
#include "include/rriccio/scoreText.h"
#include "include/rriccio/substitution.h"

#ifndef NOPYTHON
#include <pybind11/pybind11.h>
namespace py = pybind11;
#endif

using namespace std;

PlayfairCrack::PlayfairCrack(const char* ngramsFile)
{	// get file as string
	file = string(ngramsFile);
}

const char* PlayfairCrack::crack(const char* newCiphertext, int iterations, 
	                             float temp, float step, float fudgeFactor, float threshold)
{	// random seed and set vars
	srand(static_cast<unsigned int>(time(0)));
	ciphertext = string(newCiphertext);
	auto score = ScoreText(file.c_str());

	string decrypted, testKey;
	double currentScore, probability;
	double deltaFitness = 0.0;
	
	// use simulated annealing as described in practicalcryptography.com
	// simulated annealing allows possibly bad keys to be kept in order to overcome local maximum
	for (float currentTemp = temp; currentTemp >= 0; currentTemp -= step)
	{
		for (int count{ 0 }; count < iterations; count++)
		{
			// modify key
			testKey = bestKey;
			modifyKey(testKey);

			// decrypt and score
			decrypted = playfairDecrypt(testKey);
			currentScore = score.checkFitness(decrypted);
			deltaFitness = currentScore - maxFitness;

			// if the key is better, keep it
			if (deltaFitness >= 0)
			{
				maxFitness = currentScore;
				bestKey = testKey;
			}
			else if (currentTemp > 0)
			{	// when the key is worse, use e^(dT/T) to get the probability of the key being kept
				// a fudge factor closer to 1 will keep less bad keys and generally require less iterations
				probability = exp(deltaFitness / currentTemp) - fudgeFactor;
				if (probability > 1.0 * rand() / RAND_MAX)
				{
					maxFitness = currentScore;
					bestKey = testKey;
				}
			}
		}
		// once our score hits the threshold, we are done
		cout << '\r' << bestKey << '\t' << maxFitness;
		if (maxFitness > threshold)
		{
			break;
		}
	}
	cout << endl;
	const char* deciphered = decrypted.c_str();
	return deciphered;
}

string PlayfairCrack::playfairDecrypt(string& key) const
{	// same playfair decrypt as in python, yet a bit more optimized
	size_t delta_col;
	size_t idxA, idxB;
	size_t rowA, rowB;
	size_t colA, colB;
	string decrypted{ "" };

	for (size_t idx{ 0 }; idx < ciphertext.length(); idx += 2)
	{
		idxA = key.find(ciphertext[idx]);
		idxB = key.find(ciphertext[idx + 1]);
		rowA = idxA / 5;
		rowB = idxB / 5;
		colA = idxA % 5;
		colB = idxB % 5;

		if (colA == colB)
		{
			decrypted += key[((5 + (rowA - 1)) % 5) * 5 + colA];
			decrypted += key[((5 + (rowB - 1)) % 5) * 5 + colB];
		}
		else if (rowA == rowB)
		{
			decrypted += key[rowA * 5 + (5 + (colA - 1)) % 5];
			decrypted += key[rowB * 5 + (5 + (colB - 1)) % 5];
		}
		else
		{
			delta_col = colA - colB;
			decrypted += key[rowA * 5 + (colA - delta_col)];
			decrypted += key[rowB * 5 + (colB + delta_col)];
		}
	}
	removeQs(decrypted);
	return decrypted;
}

// key modifiers
void PlayfairCrack::exchange2letters(string& key) const
{
	int randomChar1{ rand() % 25 };
	int randomChar2{ rand() % 25 };
	swap(key[randomChar1], key[randomChar2]);
}

void PlayfairCrack::swap2rows(string& key) const
{
	int randomRow1{ rand() % 5 };
	int randomRow2{ rand() % 5 };
	for (size_t idx{ 0 }; idx < 5; idx += 1)
	{
		swap(key[randomRow1 * 5 + idx], key[randomRow2 * 5 + idx]);
	}
}

void PlayfairCrack::swap2cols(string& key) const
{
	int randomCol1{ rand() % 5 };
	int randomCol2{ rand() % 5 };
	for (size_t idx{ 0 }; idx < 5; idx += 1)
	{
		swap(key[idx * 5 + randomCol1], key[idx * 5 + randomCol2]);
	}
}

void PlayfairCrack::swapAllCols(string& key) const
{
	for (size_t idx{ 0 }; idx < 5; idx += 1)
	{
		swap(key[idx * 5], key[idx * 5 + 4]);
	}
	for (size_t idx{ 0 }; idx < 5; idx += 1)
	{
		swap(key[idx * 5 + 1], key[idx * 5 + 3]);
	}
}

void PlayfairCrack::swapAllRows(string& key) const
{
	for (size_t idx{ 0 }; idx < 5; idx += 1)
	{
		swap(key[idx], key[4 * 5 + idx]);
	}
	for (size_t idx{ 0 }; idx < 5; idx += 1)
	{
		swap(key[5 + idx], key[3 * 5 + idx]);
	}
}

void PlayfairCrack::modifyKey(string& key) const
{
	int choice = rand() % 50;
	switch (choice) 
	{
	case 0: 
		swap2rows(key); 
		break;
	case 1: 
		swap2cols(key);
		break;
	case 2:
		swapAllCols(key);
		swapAllRows(key);
		break;
	case 3:
		swapAllCols(key);
		break;
	case 4:
		swapAllRows(key);
		break;
	default:
		exchange2letters(key);
	}
}

void PlayfairCrack::removeQs(string& plaintext) const
{
	for (size_t idx{ 1 }; idx < plaintext.length() - 1; idx += 1)
	{
		if (toupper(plaintext[idx]) == 'Q')
		{
			if (plaintext[idx - 1] == plaintext[idx + 1])
				plaintext.erase(idx, 1);
		}
	}
}

// multithreaded thread worker
void mt_c_crack_Thread(PlayfairCrack& cracker, mutex& mtx, int iterations, float temp,
	                   float step, float fudgeFactor, float threshold)
{
	// give a score object to each thread
	auto score = ScoreText(cracker.file.c_str());

	string decrypted, testKey;
	double currentScore, probability;
	double deltaFitness = 0.0;

	// normal simmulated annealing, yet with locks
	for (float currentTemp = temp; currentTemp >= 0; currentTemp -= step)
	{
		for (int count{ 0 }; count < iterations; count++)
		{	// mutex lock sucks (it locks all threads, not just the data member) but it is easy and works for what we're doing
			mtx.lock();
			testKey = cracker.bestKey;
			mtx.unlock();
			cracker.modifyKey(testKey);
			decrypted = cracker.playfairDecrypt(testKey);
			currentScore = score.checkFitness(decrypted);
			mtx.lock();
			deltaFitness = currentScore - cracker.maxFitness;
			mtx.unlock();
			if (deltaFitness >= 0)
			{
				mtx.lock();
				cracker.maxFitness = currentScore;
				cracker.bestKey = testKey;
				mtx.unlock();
			}
			else if (currentTemp > 0)
			{
				probability = exp(deltaFitness / currentTemp) - fudgeFactor;
				if (probability > 1.0 * rand() / RAND_MAX)
				{
					mtx.lock();
					cracker.maxFitness = currentScore;
					cracker.bestKey = testKey;
					mtx.unlock();
				}
			}
		}
		mtx.lock();
		cout << '\r' << cracker.bestKey << '\t' << cracker.maxFitness;
		if (cracker.maxFitness > threshold)
		{
			mtx.unlock();
			break;
		}
		mtx.unlock();
	}
}

const char* mt_c_crack(PlayfairCrack& cracker, const char* newCiphertext, int iterations = 5000, float temp = 30.0,
	float step = 0.2, float fudgeFactor = 0.75, float threshold = 95)
{
	// take control over the python interpreter lock
	py::gil_scoped_release release;
	mutex mtx;	// shared lock
	vector<thread> threads;
	cracker.ciphertext = string(newCiphertext);
	srand(static_cast<unsigned int>(time(0)));	// make sure seed is new

	// create 10 threads
	for (size_t i{ 0 }; i < 10; i++)
	{
		threads.push_back(thread(mt_c_crack_Thread, ref(cracker), ref(mtx), iterations, temp, step, fudgeFactor, threshold));
	}
	for (auto& current_thread : threads)
	{	// wait for threads
		current_thread.join();
	}
	cout << endl;
	py::gil_scoped_acquire aquire;	// give lock back to interpreter
	const char* decrypted = cracker.playfairDecrypt(cracker.bestKey).c_str();	// convert to c string to allow happiness with C
	return decrypted;
}

#ifndef __cplusplus
extern "C"
{	// define our methods as callable from C
	const char* crack(const char* file, const char* newCiphertext, int iterations,
		float temp, float step, float fudgeFactor, float threshold)
	{
		PlayfairCrack cracker = PlayfairCrack(file);
		return cracker.crack(newCiphertext, iterations, temp, step, fudgeFactor, threshold);
	}
}
#endif

#ifndef NOPYTHON
// generate python bindings
PYBIND11_MODULE(cryptanalysis, m)
{
	m.doc() = "C Code for cracking a given ciphertext (playfair/substitution).";
	// const char* newCiphertext, int iterations, 
	// float temp, float step, float fudgeFactor, float threshold
	py::class_<PlayfairCrack>(m, "PlayfairCrack")
		.def(py::init<const char*>())
		.def("c_crack", &PlayfairCrack::crack, "single threaded crack method",
			py::arg("ciphertext"), py::arg("iterations") = 50000, py::arg("temp") = 30, py::arg("step") = 0.2, py::arg("fudge") = 0.5, py::arg("threshold") = 95)
		;

	py::class_<SubstitutionCrack>(m, "SubstitutionCrack")
		.def(py::init<const char*>())
		.def("c_crack", &SubstitutionCrack::crack, "single threaded crack method",
			py::arg("ciphertext"), py::arg("iterations") = 2000, py::arg("threshold") = 3)
		;

	py::class_<ScoreText>(m, "ScoreText")
		.def(py::init<const char*>())
		.def("c_score", &ScoreText::checkFitness, "score text",
			py::arg("text"));

	m.def("mt_c_crack", &mt_c_crack,
		py::arg("crackobj"), py::arg("ciphertext"), py::arg("iterations") = 3000, py::arg("temp") = 30, py::arg("step") = 0.2, py::arg("fudge") = 0.75, py::arg("threshold") = 95);
}
#endif

