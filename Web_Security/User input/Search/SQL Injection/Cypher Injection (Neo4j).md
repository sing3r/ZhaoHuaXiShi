---
attack_surface: [注入类]
impact: [信息泄露, 权限提升]
risk_level: 高
prerequisites:
  - Neo4j / Cypher 查询语言基础
difficulty: 高级
related_techniques:
  - sql-injection
  - nosql-injection
  - orm-injection
tools:
  - Burp Suite
---

# Cypher Injection (Neo4j)

> 关联文档：[SQL Injection 总览](../README.md) · [NoSQL Injection](../../NoSQL%20Injection/README.md) · [ORM Injection](../../ORM%20Injection/README.md)

---

Cypher 是 Neo4j 图数据库的查询语言，类似于 SQL 之于关系型数据库。当用户输入拼接到 Cypher 查询字符串时，攻击者可以注入图查询操作符。

## 学习资源

- [Varonis — Neo4jection: Secrets, Data and Cloud Exploits](https://www.varonis.com/blog/neo4jection-secrets-data-and-cloud-exploits)
- [The Most Underrated Injection of All Time — Cypher Injection](https://infosecwriteups.com/the-most-underrated-injection-of-all-time-cypher-injection-fa2018ba0de8)
