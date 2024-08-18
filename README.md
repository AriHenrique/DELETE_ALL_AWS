# AWS Resource Cleanup Script

Este script Python é projetado para deletar uma ampla gama de recursos em uma conta AWS. Ele utiliza a biblioteca `boto3` para interagir com a AWS e realiza a exclusão de recursos de vários serviços. Use este script com cautela, pois ele fará a exclusão irreversível de muitos recursos críticos na sua conta AWS.

## Recursos Deletados

O script executa a exclusão dos seguintes recursos:

---
### Amazon EC2
- **Pares de Chaves EC2**: Deleta todos os pares de chaves.
- **Volumes EBS**: Deleta todos os volumes EBS que estão em estado `available`.
- **Instâncias EC2**: Termina todas as instâncias EC2.
- **VPCs**: Deleta todas as VPCs, incluindo sub-redes, grupos de segurança, tabelas de roteamento e gateways de internet associados.

---
### Amazon S3
- **Buckets S3**: Deleta todos os buckets S3, incluindo todos os objetos dentro deles.

---
### AWS IAM
- **Usuários IAM**: Deleta todos os usuários IAM, exceto o usuário especificado como `exclude` no script. Remove todas as chaves de acesso, políticas e grupos associados.
- **Grupos IAM**: Deleta todos os grupos IAM, removendo todas as políticas associadas.
- **Roles IAM**: Deleta todas as roles IAM, exceto roles gerenciadas pela AWS. Remove todas as políticas associadas.
- **Provedores de Identidade IAM**: Deleta todos os provedores de identidade (OpenID Connect e SAML).
- **Políticas Gerenciadas pelo Cliente**: Deleta todas as políticas gerenciadas pelo cliente.
- **Políticas Inline**: Deleta todas as políticas inline associadas a usuários, grupos e roles.

---
### AWS Glue
- **Jobs Glue**: Deleta todos os jobs no AWS Glue.
- **Crawlers Glue**: Deleta todos os crawlers no AWS Glue.
- **Conectores Glue**: Deleta todos os conectores personalizados no AWS Glue.

---
### Amazon Athena
- **Bancos de Dados Athena**: Deleta todos os bancos de dados e tabelas associados no Glue Data Catalog.

---
### AWS Lambda
- **Funções Lambda**: Deleta todas as funções Lambda.

---
### Amazon RDS
- **Instâncias RDS**: Deleta todas as instâncias RDS sem salvar um snapshot final.

---
### Amazon DynamoDB
- **Tabelas DynamoDB**: Deleta todas as tabelas no DynamoDB.

---
### Amazon SQS
- **Filas SQS**: Deleta todas as filas SQS.

---
### Amazon SNS
- **Tópicos SNS**: Deleta todos os tópicos SNS.

---
### AWS Secrets Manager
- **Segredos Secrets Manager**: Deleta todos os segredos no AWS Secrets Manager.

---
### Amazon CloudWatch
- **Grupos de Logs CloudWatch**: Deleta todos os grupos de logs no CloudWatch.
- **Alarmes CloudWatch**: Deleta todos os alarmes no CloudWatch.

---
### AWS Step Functions
- **Máquinas de Estado Step Functions**: Deleta todas as máquinas de estado no Step Functions.

---
### AWS Lake Formation
- **Recursos do Lake Formation**: Revoga permissões e deleta todas as configurações e bancos de dados/tabelas controlados pelo Lake Formation.

---
### Amazon Route 53
- **Zonas Hospedadas do Route 53**: Deleta todas as zonas hospedadas e registros DNS, exceto os registros NS e SOA.

---
### Amazon ECR
- **Repositórios ECR**: Deleta todos os repositórios de contêineres no ECR.

---
### Amazon DMS
- **Tarefas de Replicação DMS**: Deleta todas as tarefas de replicação do DMS.
- **Endpoints DMS**: Deleta todos os endpoints DMS.
- **Instâncias de Replicação DMS**: Deleta todas as instâncias de replicação do DMS.

---
### Amazon EventBridge
- **Regras EventBridge**: Deleta todas as regras de eventos do Amazon EventBridge.

---
### AWS CodeBuild
- **Projetos CodeBuild**: Deleta todos os projetos no AWS CodeBuild.

---
### AWS CodeCommit
- **Repositórios CodeCommit**: Deleta todos os repositórios no AWS CodeCommit.

---
### AWS CodePipeline
- **Pipelines CodePipeline**: Deleta todas as pipelines no AWS CodePipeline.

---
### AWS CodeStar
- **Projetos CodeStar**: Deleta todos os projetos no AWS CodeStar.

---
## Como Usar

Execute o script com o seguinte comando:

```bash
python3 script_name.py seu-user-cli-aws # usuario para ser ignorado para nao deletar ele durante as execucoes

