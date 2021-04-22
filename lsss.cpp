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
// Query Tree structure
struct QueryTree
{
    string value;
    QueryTree* left, *right;
    vector<int> vec;
    int is_leaf;
};
// create new node
QueryTree* newNode(string v,int is_leaf)
{
    //QueryTree *temp = (QueryTree*)malloc(sizeof(QueryTree));
    QueryTree *temp = new QueryTree;
    temp->left = temp->right = NULL;
    temp->value = v;
    temp->is_leaf = is_leaf;
    return temp;
};
// check if string is operator
bool isOperator(string c)
{
    if (c == "AND" || c == "OR" || c == "and" || c == "or")
        return true;
    return false;
}
// print tree in level order traveral
int height(QueryTree* node)
{
    if (node == NULL)
        return 0;
    else
    {
        /* compute the height of each subtree */
        int lheight = height(node->left);
        int rheight = height(node->right);
 
        /* use the larger one */
        if (lheight > rheight)
            return(lheight + 1);
        else return(rheight + 1);
    }
}
void printGivenLevel(QueryTree* root, int level)
{
    if (root == NULL)
        return;
    if (level == 1)
    {
	cout<<"{ ";
        cout << root->value << " ";
	for(int i=0;i<(root->vec).size();i++)
		cout<<(root->vec)[i]<<"  ";
	cout<<" }";
    }
    else if (level > 1)
    {
        printGivenLevel(root->left, level-1);
        printGivenLevel(root->right, level-1);
    }
}
void printLevelOrder(QueryTree* root)
{
    int h = height(root);
    int i;
    for (i = 1; i <= h; i++)
    {
        printGivenLevel(root, i);
	cout<<endl;
    }
}
void inOrder(QueryTree *root,map<string,vector<int>> &LSSS)
{
	if(root != NULL)
	{
		inOrder(root->left,LSSS);
		cout<<"{ ";
		cout<<root->value<<" ";
		for(int i=0;i<(root->vec).size();i++)
			cout<<(root->vec)[i]<<"  ";
		cout<<" }";
		if (!isOperator(root->value))
			LSSS[root->value] = root->vec;
		inOrder(root->right,LSSS);
	}
}
// create query tree
QueryTree* constructTree(vector<string> postfix)
{
    stack<QueryTree*> st;
    QueryTree *t, *t1, *t2;
 
    // Traverse through every character of
    // input expression
    for (int i=0; i<postfix.size(); i++)
    {
        // If operand, simply push into stack
        if (!isOperator(postfix[i]))
        {
            t = newNode(postfix[i],1);
            st.push(t);
        }
        else // operator
        {
            t = newNode(postfix[i],0);
            // Pop two top nodes
            t1 = st.top(); // Store top
            st.pop();      // Remove top
            t2 = st.top();
            st.pop();
 
            //  make them children
            t->right = t1;
            t->left = t2;
 
            // Add this subexpression to stack
            st.push(t);
        }
    }
 
    //  only element will be root of expression
    // tree
    t = st.top();
    st.pop();
 cout<<"Created tree successfully\n";
    return t;
}

QueryTree* childv(QueryTree*root,int* maxL);
QueryTree* orchild(QueryTree* node,vector<int> vector_from_parent,int *maxL);
QueryTree* leftandchild(QueryTree* node,vector<int> vector_from_parent,int *maxL);
QueryTree* rightandchild(QueryTree* node,vector<int> vector_from_parent,int *maxL);

//LSSS
QueryTree* rightandchild(QueryTree* node,vector<int> vector_from_parent,int *maxL)
{	
	int length = vector_from_parent.size()+1;
	//int length = (node->vec).size()+1;	
	(node->vec).clear();
	for(int i=0;i<length-1;i++)
		(node->vec).push_back(0);
	(node->vec).push_back(-1);
	if((node->vec).size() > *maxL)
		*maxL = (node->vec).size();
	node = childv(node, maxL);
	return node;
}

QueryTree* leftandchild(QueryTree* node,vector<int> vector_from_parent,int *maxL)
{
	(node->vec).clear();
	for(int i=0;i<vector_from_parent.size();i++)
		(node->vec).push_back(vector_from_parent[i]);
	(node->vec).push_back(1);
	if((node->vec).size() > *maxL)
		*maxL = (node->vec).size();
	node = childv(node, maxL);
	return node;
}
QueryTree* orchild(QueryTree* node,vector<int> vector_from_parent,int *maxL)
{
	(node->vec).clear();
	for(int i=0;i<vector_from_parent.size();i++)
		(node->vec).push_back(vector_from_parent[i]);
	node = childv(node, maxL);
	return node;
}
QueryTree* childv(QueryTree* root,int* maxL)
{
	if(root->value == "OR" || root->value == "or")
	{
		root->left = orchild(root->left,root->vec,maxL);
		root->right = orchild(root->right,root->vec,maxL);
	}
	if(root->value == "AND" || root->value == "and")
	{
		root->left = leftandchild(root->left,root->vec,maxL);
		root->right = rightandchild(root->right,root->vec,maxL);
	}
	return root;
}
QueryTree* padding(QueryTree*root,int* maxL)
{
	if((root->vec).size() < *maxL)
	{
		int pads = *maxL - (root->vec).size();
		for(int i=0;i<pads;i++)
			(root->vec).push_back(0);
	}
	if(root->is_leaf == 0)
	{
		root->left = padding(root->left,maxL);
		root->right = padding(root->right,maxL);
	}
	return root;
}
QueryTree* LSSS(QueryTree *root)
{
	if(root != NULL)
	{
		int maxL = 0;
		if(root->is_leaf == 1)
			return root;
		else
		{
			root = childv(root,&maxL);
			cout<<maxL;	
			root = padding(root,&maxL);
		}
	}
}
int main()
{
	char a[200];
	cout<<"Enter query: ";
	scanf("\n");
	scanf("%[^\n]s",a);
	vector<string> words;
	char *pch;
	pch = strtok(a," ");
	while(pch != NULL)
	{
		words.push_back(convert_to_String(pch));
		pch = strtok(NULL," ");
	}
	cout<<"Following are the words in the query:\n";
	for(int i=0;i<words.size();i++)
		cout<<words[i]<<endl;
	cout<<"-----------------------------------------------\n";
	QueryTree* r = constructTree(words);
	r = LSSS(r);
	map<string,vector<int>> LSSS;
	cout<<"\nFollowing is the level order traversal of query:\n";
	printLevelOrder(r);
	cout<<"-----------------------------------------------";
	cout<<"\nFollowing is the in order traversal of query:\n";
	inOrder(r,LSSS);
	cout<<"\n-----------------------------------------------\n";
	cout<<"\nFollowing is the LSSS matrix:\n";
	for(auto i: LSSS)
	{
		cout<<"Attribute: "<<i.first<<"\t";
		cout<<"Vector: [";
		for(int j=0;j<i.second.size();j++)
			cout<<i.second[j]<<" ";
		cout<<"]"<<endl;
	}
	cout<<"\n-----------------------------------------------\n";
	return 0;
}
