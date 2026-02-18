#include <stdio.h>

int n, m;
int knows[51];
int party[51][51];
int size[51];
int adj[51][51];

void dfs(int p) { // for the person
    for (int i = 1; i <= n; i++) {
        if (adj[p][i] && !knows[i]) {
            knows[i] = 1;
            dfs(i);
        }
    }
}

int main() {
    scanf("%d %d", &n, &m);

    int truth, init[51];
    scanf("%d", &truth);

    for (int i = 0; i < truth; i++) {
        scanf("%d", &init[i]);
        knows[init[i]] = 1;
    }

    for (int i = 0; i < m; i++) {
        scanf("%d", &size[i]);
        for (int j = 0; j < size[i]; j++) {
            scanf("%d", &party[i][j]);
        }

        for (int j = 0; j < size[i]; j++) {
            for (int k = 0; k < size[i]; k++) {
                adj[party[i][j]][party[i][k]] = 1;
            }
        }
    }

    for (int i = 0; i < truth; i++) {
        dfs(init[i]);
    }

    int res = 0;
    for (int i = 0; i < m; i++) {
        int flag = 1; // true
        for (int j = 0; j < size[i]; j++) {
            if (knows[party[i][j]]) {
                flag = 0;
                break;
            }
        }

        if (flag) res++;
    }

    printf("%d", res);

    return 0;
}