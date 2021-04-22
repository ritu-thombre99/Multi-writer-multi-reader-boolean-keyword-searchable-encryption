#include "pbc.h"
#include<gmp.h>
#include "pbc_test.h"
#include<time.h>
using namespace std;
#include<bits/stdc++.h>
#include<algorithm>
#include<iostream>
#include<string.h>
#include<vector>
#define KEYWORD_SIZE 10

unordered_map<string,mpz_t> keywords;

// definition of public parameters
typedef struct public_parameter_def
{
	mpz_t N;
	mpz_t g;
	int n;
	unordered_map<string,mpz_t> KS;
} public_parameter;

// initialization of public parameters
public_parameter initialize_pp(public_parameter pp)
{
	mpz_init(pp.N);
	mpz_init(pp.g);
	return pp;
}

// assignment of public parameters
public_parameter assign_pp(public_parameter pp,mpz_t N,mpz_t g,unordered_map<string,mpz_t> keywords)
{
	mpz_set(pp.N,N);
	mpz_set(pp.g,g);
	pp.n = keywords.size();
	for (auto i: keywords)
	{
		mpz_init(pp.KS[i.first]);
		mpz_set(pp.KS[i.first],keywords[i.first]);
	}
	return pp;
}

// definition of master public key
typedef struct mpk_def
{
	mpz_t N;
	mpz_t g;
	mpz_t g_to_the_alpha;
	mpz_t H[KEYWORD_SIZE];
	mpz_t X4;
}master_public_key;

// initialization of master public key
master_public_key initialize_mpk(master_public_key mpk)
{
	mpz_init(mpk.N);
	mpz_init(mpk.g);
	mpz_init(mpk.g_to_the_alpha);
	for(int i=0;i<KEYWORD_SIZE;i++)
		mpz_init(mpk.H[i]);
	mpz_init(mpk.X4);
	return mpk;
}

// assignment of master public key
master_public_key assign_mpk(master_public_key mpk,mpz_t N,mpz_t g,mpz_t g_to_the_alpha,mpz_t H[],mpz_t X4)
{
	mpz_set(mpk.N,N);
	mpz_set(mpk.g,g);
	mpz_set(mpk.g_to_the_alpha,g_to_the_alpha);
	for(int i=0;i<KEYWORD_SIZE;i++)
		mpz_set(mpk.H[i],H[i]);
	mpz_set(mpk.X4,X4);
	return mpk;
}

// definition of master secret key
typedef struct msk_def
{
	mpz_t alpha;
	mpz_t u_prime[KEYWORD_SIZE];
	mpz_t u[KEYWORD_SIZE];
	mpz_t X3;
}master_secret_key;

// initialization of master secret key
master_secret_key initialize_msk(master_secret_key msk)
{
	mpz_init(msk.alpha);
	for(int i=0;i<KEYWORD_SIZE;i++)
	{
		mpz_init(msk.u_prime[i]);
		mpz_init(msk.u[i]);
	}
	mpz_init(msk.X3);
	return msk;
}

// assignment of master secret key
master_secret_key assign_msk(master_secret_key msk,mpz_t alpha,mpz_t u_prime[],mpz_t u[],mpz_t X3)
{
	mpz_set(msk.alpha,alpha);
	for(int i=0;i<KEYWORD_SIZE;i++)
	{
		mpz_set(msk.u_prime[i],u_prime[i]);	
		mpz_set(msk.u[i],u[i]);
	}
	mpz_set(msk.X3,X3);
	return msk;
}

// WRITER registration
void register_writer(unordered_map<int,mpz_t> &writer_list,unordered_map<int,mpz_t> &writer_server_keys,unordered_map<int,mpz_t> &writer_private_keys,
	int wid,public_parameter pp,master_public_key mpk, gmp_randstate_t state)
{
	// writer secret key
	mpz_t x_wid;
	mpz_init(x_wid);
	mpz_urandomm(x_wid,state,mpk.N);
	mpz_init(writer_private_keys[wid]);
	mpz_set(writer_private_keys[wid],x_wid);
	// server-writer key
	mpz_t y_wid;
	mpz_init(y_wid);
	mpz_powm(y_wid,mpk.g,x_wid,mpk.N);
	mpz_invert(y_wid,y_wid,mpk.N);
	mpz_init(writer_server_keys[wid]);
	mpz_set(writer_server_keys[wid],y_wid);
	// update writer list
	mpz_init(writer_list[wid]);
	mpz_set(writer_list[wid],y_wid);
	
}

// WRITER deregistration
void deregister_writer(unordered_map<int,mpz_t> &writer_list,unordered_map<int,mpz_t> &writer_server_keys,unordered_map<int,mpz_t> &writer_private_keys,int wid_to_delete)
{
	writer_list.erase(wid_to_delete);
	writer_private_keys.erase(wid_to_delete);
	writer_server_keys.erase(wid_to_delete);	
	
}

// definition of READER SECRET KEY
typedef struct reader_secret_key_def
{
	mpz_t x_rid;
	mpz_t u[KEYWORD_SIZE];
	mpz_t u_prime_rid[KEYWORD_SIZE];
}reader_secret_key;

// initialization of READER SECRET KEY
reader_secret_key initialize_reader_secret_key(reader_secret_key u_rid)
{
	mpz_init(u_rid.x_rid);
	for(int i=0;i<KEYWORD_SIZE;i++)
	{
		mpz_init(u_rid.u[i]);
		mpz_init(u_rid.u_prime_rid[i]);
	}
	return u_rid;
}

// definition of READER SERVER KEY
typedef struct reader_server_key_def
{
	int rid;
	mpz_t y_rid;
	mpz_t x_prime_rid;
}reader_server_key;

// initialization of READER SERVER KEY
reader_server_key initialize_reader_server_key(reader_server_key s_rid)
{
	mpz_init(s_rid.y_rid);
	mpz_init(s_rid.x_prime_rid);		
	return s_rid;
}

// READER registration
void register_reader(unordered_map<int,reader_secret_key> &reader_private_keys,unordered_map<int,reader_server_key> &reader_server_keys,unordered_map<int,reader_server_key> &reader_list,
	int rid,public_parameter pp,master_public_key mpk,master_secret_key msk,gmp_randstate_t state,pairing_t pairing_final)
{
	mpz_t x_rid,x_prime_rid;
	mpz_init(x_rid);
	mpz_init(x_prime_rid);
	mpz_urandomm(x_rid,state,mpk.N);
	mpz_urandomm(x_prime_rid,state,mpk.N);
	element_t y,a,b;
	element_init_Zr(y, pairing_final);
	element_init_Zr(a, pairing_final);
	element_init_Zr(b, pairing_final);
	element_set_mpz(a,msk.alpha);
	element_set_mpz(b,x_rid);
	element_div(y,a,b);
	mpz_t y_rid;
	mpz_init(y_rid);
	element_to_mpz(y_rid,y);
	mpz_t u_prime_rid[KEYWORD_SIZE];
	
	unsigned long int x_prime_rid_th_root=mpz_get_ui(x_prime_rid);
	for(int i=0;i<KEYWORD_SIZE;i++)
	{
		mpz_init(u_prime_rid[i]);
		mpz_root(u_prime_rid[i],msk.u_prime[i],x_prime_rid_th_root);
	}
	reader_secret_key u_rid = initialize_reader_secret_key(u_rid);
	mpz_set(u_rid.x_rid,x_rid);
	for(int i=0;i<KEYWORD_SIZE;i++)
	{
		mpz_set(u_rid.u[i],msk.u[i]);
		mpz_set(u_rid.u_prime_rid[i],u_prime_rid[i]);
	}
	reader_private_keys[rid] = u_rid;
	

	reader_server_key s_rid = initialize_reader_server_key(s_rid);
	s_rid.rid = rid;
	mpz_set(s_rid.y_rid,y_rid);
	mpz_set(s_rid.x_prime_rid,x_prime_rid);
	reader_server_keys[rid] = s_rid;
	reader_list[rid] = s_rid;
}

// READER deregistration
void deregister_reader(unordered_map<int,reader_secret_key> &reader_private_keys,unordered_map<int,reader_server_key> &reader_server_keys,
	unordered_map<int,reader_server_key> &reader_list,int rid_to_delete)
{

	reader_list.erase(rid_to_delete);
	reader_private_keys.erase(rid_to_delete);
	reader_server_keys.erase(rid_to_delete);	
	
}

// print READERS
void print_readers(unordered_map<int,reader_server_key> reader_list)
{
	if(reader_list.empty()==true)
		cout<<"No readers found\n";
	else
	{
		for(auto i: reader_list)
		{
			cout<<"Reader ID :"<<i.first<<endl;
			gmp_printf("y_rid : %Zd\n",i.second.y_rid);
			gmp_printf("x_prime_rid : %Zd\n",i.second.x_prime_rid);
			cout<<"--------------------------------------\n";
		}
	}
}

// print WRITERS
void print_writers(unordered_map<int,mpz_t> writer_list)
{
	if(writer_list.empty()==true)
		cout<<"No writers found\n";
	else
	{
		for(auto i: writer_list)
		{
			cout<<"Writer ID :"<<i.first<<endl;
			gmp_printf("y_wid : %Zd\n",i.second);
			cout<<"--------------------------------------\n";
		}
	}
}

// preprocessing input 
string getString(char X)
{
	string s(1,X);
	return s;
}
string convert_to_String(char char_str[])
{
	string str;
	for (int i=0;i<strlen(char_str);i++)
		str = str + getString(char_str[i]);
	return str;
}

// encrypt
typedef struct ciphertext_type
{
	element_t C0;
	mpz_t C0_prime;
	mpz_t C[KEYWORD_SIZE],C_prime[KEYWORD_SIZE];
	string message;
	int word_size;
	
}ciphertext;
ciphertext initialize_cc(ciphertext cc,pairing_t pairing1)
{
	element_init_GT(cc.C0,pairing1);
	mpz_init(cc.C0_prime);
	for(int i=0;i<KEYWORD_SIZE;i++)
	{
		mpz_init(cc.C[i]);
		mpz_init(cc.C_prime[i]);
	}
	return cc;
}
void c_accept(ciphertext cc,unordered_multimap<int,ciphertext> &SS,int wid_writer,unordered_map<int,mpz_t> writer_list,mpz_t N)
{
	int word_size = cc.word_size;
	for(int i=0;i<word_size;i++)
	{
		mpz_mul(cc.C[i],cc.C[i],writer_list[wid_writer]);
		mpz_mod(cc.C[i],cc.C[i],N);
	}
	SS.insert({wid_writer,cc});
}
void encrypt(const master_public_key mpk,master_secret_key msk,mpz_t W[],string M,int wid_writer,unordered_multimap<int,ciphertext> &SS,
	int word_size,gmp_randstate_t state,pairing_t pairing1,pairing_t pairing2,pairing_t pairing3,pairing_t pairing4,pairing_t pairing_final,
	mpz_t p1,mpz_t p2,mpz_t p3,mpz_t p4,mpz_t N,unordered_map<int,mpz_t> writer_private_keys,unordered_map<int,mpz_t> writer_list)
{
	mpz_t s;
	mpz_init(s);
	mpz_urandomm(s,state,N);
	mpz_t h,Z0,Z1[word_size],Z1_prime[word_size];
	
	mpz_init(h);
	mpz_urandomm(h,state,p4);
	
	mpz_init(Z0);
	mpz_urandomm(Z0,state,p4);

	for(int i=0;i<word_size;i++)
	{
		mpz_init(Z1[i]);
		mpz_urandomm(Z1[i],state,p4);
		mpz_init(Z1_prime[i]);
		mpz_urandomm(Z1_prime[i],state,p4);
	}
	//cout<<"Created required variables\n";
	element_t g,g_to_the_alpha;

	element_init_G1(g, pairing1);
	element_init_G2(g_to_the_alpha, pairing1);
	
	mpz_t temp_g,temp_g_to_the_alpha;
	mpz_init(temp_g);
	mpz_init(temp_g_to_the_alpha);
	mpz_set(temp_g,mpk.g);
	mpz_set(temp_g_to_the_alpha,mpk.g_to_the_alpha);
	element_from_hash(g,temp_g,mpz_get_ui(p1));
	element_from_hash(g_to_the_alpha,temp_g_to_the_alpha,mpz_get_ui(p1));
	element_t C0;
	element_init_GT(C0, pairing1);
	
	pairing_apply(C0, g, g_to_the_alpha, pairing1);
	element_pow_mpz(C0,C0,s);
	//cout<<"Created C0\n";
	
	mpz_t C0_prime;
	mpz_init(C0_prime);
	mpz_mul(C0_prime,mpk.g,h);
	mpz_mod(C0_prime,C0_prime,N);
	mpz_powm(C0_prime,C0_prime,s,N);
	mpz_mul(C0_prime,C0_prime,Z0);
	mpz_mod(C0_prime,C0_prime,N);
	//cout<<"Created C0_prime"<<endl;
	mpz_t C_prime[word_size];
	for(int i=0;i<word_size;i++)
	{
		mpz_init(C_prime[i]);
		mpz_powm(C_prime[i],msk.u_prime[i],s,N);
		mpz_mul(C_prime[i],C_prime[i],Z1_prime[i]);
		mpz_mod(C_prime[i],C_prime[i],N);
	}
	//cout<<"Created C_prime"<<endl;
	mpz_t C[word_size];
	for(int i=0;i<word_size;i++)
	{
		mpz_init(C[i]);
		mpz_powm(C[i],mpk.H[i],W[i],N);
		mpz_powm(C[i],C[i],s,N);		
		mpz_mul(C[i],C[i],Z1[i]);
		mpz_mod(C[i],C[i],N);
		mpz_t g_to_the_xwid;
		mpz_init(g_to_the_xwid);
		mpz_powm(g_to_the_xwid,mpk.g,writer_private_keys[wid_writer],N);
		mpz_mul(C[i],C[i],g_to_the_xwid);
		mpz_mod(C[i],C[i],N);
	}
	//cout<<"Created C"<<endl;
	ciphertext cc = initialize_cc(cc,pairing1);
	element_set(cc.C0,C0);
	mpz_set(cc.C0_prime,C0_prime);
	for(int i=0;i<word_size;i++)
	{
		mpz_set(cc.C[i],C[i]);
		mpz_set(cc.C_prime[i],C_prime[i]);
	}
	cc.word_size = word_size;
	cc.message = M;
	//cout<<"Created Ciphertext"<<endl;
	c_accept(cc,SS,wid_writer,writer_list,N);
}
//print messsages
void print_messages(unordered_multimap<int,ciphertext> &SS)
{
	if(SS.empty()==true)
		cout<<"No messages found\n";
	else
	{
		for(auto i: SS)
		{
			cout<<"Writer ID :"<<i.first<<endl;
			cout<<"Message :"<<i.second.message<<endl;
			element_printf("C0 : %B\n",i.second.C0);
			gmp_printf("C0_prime : %Zd\n",i.second.C0_prime);
			cout<<"C values:\n";
			for(int j=0;j<i.second.word_size;j++)
				gmp_printf("C[%d] : %Zd\n",j,i.second.C[j]);
			cout<<"C_prime values:\n";
			for(int j=0;j<i.second.word_size;j++)
				gmp_printf("C_prime[%d] : %Zd\n",j,i.second.C_prime[j]);
			cout<<"--------------------------------------\n";
		}
	}
}
int main(int argc, char **argv)
//int main()
{
	mpz_t r1,r2,r3,r4,p1,p2,p3,p4;
	mpz_t size_p;
	
	mpz_init(p1);
	mpz_init(p2);
	mpz_init(p3);
	mpz_init(p4);

	mpz_init(r1);
	mpz_init(r2);
	mpz_init(r3);
	mpz_init(r4);

	mpz_init(size_p);

	srand(time(0));
	mpz_set_si(size_p,rand());
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	
	// generate random numbers	
	mpz_urandomm(r1,state,size_p);
	mpz_urandomm(r2,state,size_p);
	mpz_urandomm(r3,state,size_p);
	mpz_urandomm(r4,state,size_p);

	// generate prime numbers
	mpz_nextprime(p1,r1);
	mpz_nextprime(p2,r2);
	mpz_nextprime(p3,r3);
	mpz_nextprime(p4,r4);

	mpz_t N;
	mpz_init(N);
	mpz_mul(N,p1,p2);
	mpz_mul(N,N,p3);
	mpz_mul(N,N,p4);
	
	//group G1 of order p1
	pairing_t pairing1;
	pbc_param_t param1;
	pbc_param_init_a1_gen(param1,p1);
	pairing_init_pbc_param(pairing1,param1);
	//group G2 of order p2
	pairing_t pairing2;
	pbc_param_t param2;
	pbc_param_init_a1_gen(param2,p2);
	pairing_init_pbc_param(pairing2,param2);
	//group G3 of order p3
	pairing_t pairing3;
	pbc_param_t param3;
	pbc_param_init_a1_gen(param3,p3);
	pairing_init_pbc_param(pairing3,param3);
	//group G4 of order p4
	pairing_t pairing4;
	pbc_param_t param4;
	pbc_param_init_a1_gen(param4,p4);
	pairing_init_pbc_param(pairing4,param4);
	//group GT of order N=p1*p2*p3*p4
	pairing_t pairing_final;
	pbc_param_t param_final;
	pbc_param_init_a1_gen(param_final,N);
	pairing_init_pbc_param(pairing_final,param_final);

	//double P=mpz_get_d(pairing_final->r);
	vector<string> temp;

	temp.push_back("hospital1");
	temp.push_back("hospital2");
	temp.push_back("doctor1");
	temp.push_back("doctor2");
	temp.push_back("patient1");
	temp.push_back("patient2");
	temp.push_back("disease1");
	temp.push_back("disease2");
	temp.push_back("age1");
	temp.push_back("age2");

	for(int i=0;i<temp.size();i++)
	{
		mpz_t t;
		mpz_init(t);
		mpz_set_si(t,101+i);
		mpz_init(keywords[temp[i]]);
		mpz_set(keywords[temp[i]],t);
	}
	
	
	// find apha and beta[i] values using ZN
	mpz_t alpha;
	mpz_init(alpha);
	mpz_urandomm(alpha,state,N);
	mpz_t beta[keywords.size()];
	for (int i=0;i<keywords.size();i++)
	{
		mpz_init(beta[i]);
		mpz_urandomm(beta[i],state,N);
	}
	// find g,u and u[i] values
	mpz_t g;
	mpz_init(g);
	mpz_urandomm(g,state,p1);
	mpz_t single_u;
	mpz_init(single_u);
	mpz_urandomm(single_u,state,p1);
	mpz_t u[keywords.size()];
	for (int i=0;i<keywords.size();i++)
	{
		mpz_init(u[i]);
		mpz_urandomm(u[i],state,p1);
	}
	// find X3
	mpz_t X3;
	mpz_init(X3);
	mpz_urandomm(X3,state,p3);
	// find X4 and h[i] values
	mpz_t X4;
	mpz_init(X4);
	mpz_urandomm(X4,state,p4);
	mpz_t h[keywords.size()];
	for (int i=0;i<keywords.size();i++)
	{
		mpz_init(h[i]);
		mpz_urandomm(h[i],state,p4);
	}
	// calculate u_prime[i] and H[i]
	mpz_t H[keywords.size()],u_prime[keywords.size()];	
	for (int i=0;i<keywords.size();i++)
	{
		mpz_init(H[i]);
		mpz_init(u_prime[i]);
		mpz_mul(H[i],u[i],h[i]);
		mpz_mod(H[i],H[i],N);
		mpz_powm(u_prime[i],single_u,beta[i],N);
	}
	
	public_parameter pp;
	pp = initialize_pp(pp);
	pp = assign_pp(pp,N,g,keywords);
	gmp_printf("N: %Zd\n",N);
	gmp_printf("g: %Zd\n",g);
	cout<<"\nPublic Paramater created successfully\n\n";
	mpz_t g_to_the_alpha;
	mpz_init(g_to_the_alpha);
	mpz_powm(g_to_the_alpha,g,alpha,p1);
	master_public_key mpk;
	mpk = initialize_mpk(mpk);
	mpk = assign_mpk(mpk,N,g,g_to_the_alpha,H,X4);
	gmp_printf("N: %Zd\n",N);
	gmp_printf("g: %Zd\n",g);
	gmp_printf("g^alpha: %Zd\n",g_to_the_alpha);	
	cout<<"H values:\n";
	for(int i=0;i<10;i++)
		gmp_printf("%Zd ",H[i]);
	gmp_printf("\nX4: %Zd \n",X4);
	cout<<"\nMaster public key created successfully\n\n";
	master_secret_key msk;
	msk = initialize_msk(msk);
	msk = assign_msk(msk,alpha,u_prime,u,X3);
	gmp_printf("alpha: %Zd \n",alpha);
	gmp_printf("X3: %Zd \n",X3);
	cout<<"u_prime values :\n";
	for(int i=0;i<10;i++)
		gmp_printf("%Zd ",u_prime[i]);
	cout<<"\n\nMaster secret key created successfully\n";
	unordered_map<int,mpz_t> writer_list;
	unordered_map<int,mpz_t> writer_server_keys;
	unordered_map<int,mpz_t> writer_private_keys;
	unordered_map<int,reader_secret_key> reader_private_keys;
	unordered_map<int,reader_server_key> reader_server_keys,reader_list;
	//storage servers
	unordered_multimap<int,ciphertext> SS;
	int current_wid = 0,current_rid=0;
	int choice;
	while(true)
	{
		cout<<"\n\n---------------------------------------------\n";
		cout<<"1. Register Writer\n";
		cout<<"2. Register Reader\n";
		cout<<"3. Dergister Writer\n";
		cout<<"4. Deregister Reader\n";
		cout<<"5. Print readers\n";
		cout<<"6. Print writers\n";
		cout<<"7. Write a message\n";
		cout<<"8. Print all the messages\n";
		cout<<"9. EXIT\n";
		cout<<"Enter choice:";
		cin>>choice;
		cout<<"---------------------------------------------\n";
		if(choice == 1)
		{
			current_wid++;
			register_writer(writer_list,writer_server_keys,writer_private_keys,current_wid,pp,mpk,state);
			cout<<"Registration successful. Your WID is = "<<current_wid<<"\n";
		}
		if(choice == 2)
		{
			current_rid++;
			register_reader(reader_private_keys,reader_server_keys,reader_list,current_rid,pp,mpk,msk,state,pairing_final);
			cout<<"Registration successful. Your RID is = "<<current_rid<<"\n";
		}
		if(choice == 3)
		{
			cout<<"Enter your writer ID:";
			int wid_to_delete;
			cin>>wid_to_delete;
			if(writer_list.find(wid_to_delete) != writer_list.end())	
			{	
				deregister_writer(writer_list,writer_server_keys,writer_private_keys,wid_to_delete);
				cout<<"Writer "<<wid_to_delete<<" successfully deleted\n";
			}
			else
				cout<<"Error : Writer ID not found\n";
		}
		if(choice == 4)
		{
			cout<<"Enter your reader ID:";
			int rid_to_delete;
			cin>>rid_to_delete;
			if(reader_list.find(rid_to_delete) != reader_list.end())	
			{	
				deregister_reader(reader_private_keys,reader_server_keys,reader_list,rid_to_delete);
				cout<<"Reader "<<rid_to_delete<<" successfully deleted\n";
			}
			else
				cout<<"Error : Reader ID not found\n";
		}
		if(choice == 5)
			print_readers(reader_list);
		if(choice == 6)
			print_writers(writer_list);
		if(choice == 7)
		{
			int wid_writer;
			char a[200];
			cout<<"Enter your WID :";
			cin>>wid_writer;
			if(writer_list.find(wid_writer) == writer_list.end())	
				cout<<"Unauthorized Writer!! Please register\n";		
			else
			{
				cout<<"Enter message: ";
				scanf("\n");
				scanf("%[^\n]s",a);
				vector<string> words;
				string M = convert_to_String(a);
				string M_copy = M;
				string token;
				while(token != M_copy)
				{
					token = M_copy.substr(0,M_copy.find_first_of(" "));
					M_copy = M_copy.substr(M_copy.find_first_of(" ")+1);
					words.push_back(token);
				}
				int count_attributes=0;
				for(auto i: keywords)
				{
					for(int j=0;j<words.size();j++)
					{
						if(i.first == words[j])
							count_attributes++;
					}			
				}
				mpz_t W[count_attributes];
				for(int i=0;i<count_attributes;i++)
					mpz_init(W[i]);
				int curr=0;
				for(auto i: keywords)
				{
					for(int j=0;j<words.size();j++)
					{
						if(i.first == words[j])
						{
							mpz_set(W[curr],i.second);
							curr++;
						}
					}			
				}
				//for(int i=0;i<count_attributes;i++)
				//	gmp_printf("%Zd\n",W[i]);
				if(count_attributes>0)
					encrypt(mpk,msk,W,M,wid_writer,SS,count_attributes,state,pairing1,pairing2,pairing3,pairing4,pairing_final,p1,p2,p3,p4,N,writer_private_keys,writer_list);
				else
					cout<<"Enter valid message\n";			
			}
		}
		if(choice == 8)
			print_messages(SS);
		if(choice == 9)
			break;
	}
	pairing_clear(pairing1);
	pairing_clear(pairing2);
	pairing_clear(pairing3);
	pairing_clear(pairing4);
	pairing_clear(pairing_final);
	return 0;
}
